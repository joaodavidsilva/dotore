//! Single-pass detectors for the 5 core production Rust safety rules:
//!
//! 1. `rs-no-unwrap-in-production` ([`RuleId::RsNoUnwrapInProduction`])
//! 2. `rs-no-unguarded-slice-index` ([`RuleId::RsNoUnguardedSliceIndex`])
//! 3. `rs-no-lossy-numeric-as-cast` ([`RuleId::RsNoLossyNumericAsCast`])
//! 4. `rs-require-safety-comment-on-unsafe` ([`RuleId::RsRequireSafetyCommentOnUnsafe`])
//! 5. `rs-no-mem-forget` ([`RuleId::RsNoMemForget`])

use std::collections::HashMap;

use dotore_core::{ByteSpan, RuleId, SourceLoc};
use syn::{
    BinOp, Block, Expr, ExprCall, ExprCast, ExprIf, ExprIndex, ExprMethodCall, ExprUnsafe, File,
    ImplItemFn, Item, ItemFn, ItemImpl, ItemMod, Lit, Pat, Signature, Stmt, TraitItemFn, Type,
    UnOp, UseTree,
    spanned::Spanned,
    visit::{self, Visit},
};

use crate::matchers::{
    RsCandidateFinding, RsScopeTracker, extract_pat_ident, extract_type_name, loc_at,
    normalize_expr_key, path_to_string, span_to_bytes,
};

/// Evaluates the 5 core Rust production safety rules on `ast` and appends candidate findings to `out`.
pub(crate) fn extract_safety_findings(
    ast: &File,
    lines: &[&str],
    line_starts: &[u32],
    out: &mut Vec<RsCandidateFinding>,
) {
    let mut has_imported_mem_forget = false;
    for item in &ast.items {
        if let Item::Use(item_use) = item
            && use_tree_imports_mem_forget(&item_use.tree, "")
        {
            has_imported_mem_forget = true;
        }
    }

    let mut visitor = SafetyVisitor {
        lines,
        line_starts,
        findings: out,
        scope: RsScopeTracker::for_file(ast),
        has_imported_mem_forget,
        local_types: HashMap::new(),
        fixed_array_lengths: HashMap::new(),
        active_guards: Vec::new(),
        block_guards: Vec::new(),
    };
    visitor.visit_file(ast);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NumericType {
    U8,
    U16,
    U32,
    U64,
    U128,
    Usize,
    I8,
    I16,
    I32,
    I64,
    I128,
    Isize,
    F32,
    F64,
    Bool,
    Char,
    UnsuffixedInt(i128),
}

impl NumericType {
    fn from_type_name(name: &str) -> Option<Self> {
        match name {
            "u8" => Some(Self::U8),
            "u16" => Some(Self::U16),
            "u32" => Some(Self::U32),
            "u64" => Some(Self::U64),
            "u128" => Some(Self::U128),
            "usize" => Some(Self::Usize),
            "i8" => Some(Self::I8),
            "i16" => Some(Self::I16),
            "i32" => Some(Self::I32),
            "i64" => Some(Self::I64),
            "i128" => Some(Self::I128),
            "isize" => Some(Self::Isize),
            "f32" => Some(Self::F32),
            "f64" => Some(Self::F64),
            "bool" => Some(Self::Bool),
            "char" => Some(Self::Char),
            _ => None,
        }
    }

    const fn is_float(self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    const fn is_signed_int(self) -> bool {
        matches!(
            self,
            Self::I8 | Self::I16 | Self::I32 | Self::I64 | Self::I128 | Self::Isize
        )
    }

    const fn is_unsigned_int(self) -> bool {
        matches!(
            self,
            Self::U8 | Self::U16 | Self::U32 | Self::U64 | Self::U128 | Self::Usize
        )
    }

    const fn bit_width_rank(self) -> u8 {
        match self {
            Self::Bool | Self::U8 | Self::I8 => 8,
            Self::U16 | Self::I16 => 16,
            Self::Char | Self::U32 | Self::I32 | Self::F32 => 32,
            // Treat pointer-sized integers conservatively as potentially 64-bit when narrowing to 32-bit,
            // and potentially 32-bit when narrowing from u64/i64.
            Self::Usize | Self::Isize => 48,
            Self::U64 | Self::I64 | Self::F64 => 64,
            Self::U128 | Self::I128 | Self::UnsuffixedInt(_) => 128,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SliceGuard {
    collection: String,
    index: Option<String>,
    non_empty: bool,
    inclusive_upper_bound: bool,
}

struct SafetyVisitor<'a> {
    lines: &'a [&'a str],
    line_starts: &'a [u32],
    findings: &'a mut Vec<RsCandidateFinding>,
    scope: RsScopeTracker,
    has_imported_mem_forget: bool,
    local_types: HashMap<String, NumericType>,
    fixed_array_lengths: HashMap<String, usize>,
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
                && let Some(num_ty) = extract_numeric_type(&pat_type.ty)
            {
                self.local_types.insert(ident, num_ty);
            }
        }
    }

    fn infer_expr_numeric_type(&self, expr: &Expr) -> Option<NumericType> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Expr has dozens of variants; numeric inference inspects literals, paths, calls, casts, and unary/paren expressions"
        )]
        match expr {
            Expr::Paren(paren) => self.infer_expr_numeric_type(&paren.expr),
            Expr::Group(group) => self.infer_expr_numeric_type(&group.expr),
            Expr::Path(expr_path) => {
                if expr_path.qself.is_none()
                    && let Some(ident) = expr_path.path.get_ident()
                {
                    return self.local_types.get(&ident.to_string()).copied();
                }
                None
            }
            Expr::Lit(expr_lit) => match &expr_lit.lit {
                Lit::Int(lit_int) => {
                    let suffix = lit_int.suffix();
                    if !suffix.is_empty() {
                        return NumericType::from_type_name(suffix);
                    }
                    lit_int
                        .base10_parse::<i128>()
                        .ok()
                        .map(NumericType::UnsuffixedInt)
                }
                Lit::Float(lit_float) => {
                    let suffix = lit_float.suffix();
                    if suffix == "f32" {
                        Some(NumericType::F32)
                    } else {
                        Some(NumericType::F64)
                    }
                }
                Lit::Bool(_) => Some(NumericType::Bool),
                Lit::Char(_) => Some(NumericType::Char),
                _ => None,
            },
            Expr::Unary(expr_unary) => {
                if matches!(expr_unary.op, UnOp::Neg(_)) {
                    match self.infer_expr_numeric_type(&expr_unary.expr) {
                        Some(NumericType::UnsuffixedInt(v)) => {
                            Some(NumericType::UnsuffixedInt(-v))
                        }
                        Some(other) => Some(other),
                        None => Some(NumericType::I64),
                    }
                } else {
                    self.infer_expr_numeric_type(&expr_unary.expr)
                }
            }
            Expr::MethodCall(method_call) => {
                let method_name = method_call.method.to_string();
                if matches!(
                    method_name.as_str(),
                    "len" | "count" | "capacity" | " saturating_sub" | "wrapping_add"
                ) {
                    Some(NumericType::Usize)
                } else {
                    None
                }
            }
            Expr::Cast(inner_cast) => extract_numeric_type(&inner_cast.ty),
            _ => None,
        }
    }

    fn has_safety_comment_near(&self, start_line: u32, end_line: u32) -> bool {
        if start_line == 0 || self.lines.is_empty() {
            return false;
        }
        let start_idx = usize::try_from(start_line - 1).unwrap_or(0);
        // 1. Check the `unsafe` opening line and first non-empty line inside the block
        let max_inner_idx = usize::try_from(end_line.saturating_sub(1))
            .unwrap_or(start_idx)
            .min(self.lines.len().saturating_sub(1));
        for idx in start_idx..=max_inner_idx.min(start_idx + 2) {
            if let Some(&line_str) = self.lines.get(idx)
                && line_has_safety_comment(line_str)
            {
                return true;
            }
        }

        // 2. Walk backwards above `start_line` through comments, attributes, or multi-line statement headers
        let mut cursor = start_idx;
        let mut blank_budget = 1usize;
        while cursor > 0 {
            cursor -= 1;
            let prev = self.lines[cursor].trim();
            if line_has_safety_comment(prev) {
                return true;
            }
            if prev.is_empty() {
                if blank_budget == 0 {
                    break;
                }
                blank_budget -= 1;
                continue;
            }
            if prev.starts_with("//")
                || prev.starts_with("/*")
                || prev.starts_with('*')
                || prev.starts_with("#[")
                || prev.ends_with('=')
            {
                continue;
            }
            break;
        }

        false
    }

    fn is_slice_index_guarded(&self, expr_index: &ExprIndex) -> bool {
        // Unbounded full range `&slice[..]` never panics
        if let Expr::Range(range) = expr_index.index.as_ref()
            && range.start.is_none()
            && range.end.is_none()
        {
            return true;
        }

        let coll_key = normalize_expr_key(&expr_index.expr);
        if coll_key.is_empty() {
            return false;
        }

        // Check fixed-size local array literal bounds: `let arr = [1, 2, 3]; arr[0]`
        if let Some(&known_len) = self.fixed_array_lengths.get(&coll_key)
            && let Some(NumericType::UnsuffixedInt(idx_val)) =
                self.infer_expr_numeric_type(&expr_index.index)
            && idx_val >= 0
            && usize::try_from(idx_val).is_ok_and(|u| u < known_len)
        {
            return true;
        }

        let all_guards = self.active_guards.iter().chain(self.block_guards.iter());

        if let Expr::Range(range) = expr_index.index.as_ref() {
            let end_key = range.end.as_ref().map(|e| normalize_expr_key(e));
            let start_key = range.start.as_ref().map(|e| normalize_expr_key(e));
            for g in all_guards {
                if g.collection != coll_key {
                    continue;
                }
                if let Some(ek) = &end_key
                    && g.index.as_deref() == Some(ek.as_str())
                {
                    return true;
                }
                if end_key.is_none()
                    && let Some(sk) = &start_key
                    && g.index.as_deref() == Some(sk.as_str())
                {
                    return true;
                }
            }
            return false;
        }

        let idx_key = normalize_expr_key(&expr_index.index);
        for g in all_guards {
            if g.collection != coll_key {
                continue;
            }
            if !g.inclusive_upper_bound && g.index.as_deref() == Some(idx_key.as_str()) {
                return true;
            }
            if idx_key == "0" && (g.non_empty || (!g.inclusive_upper_bound && g.index.is_some())) {
                return true;
            }
        }

        false
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
        let prev_arrays = std::mem::take(&mut self.fixed_array_lengths);
        let prev_block_guards = std::mem::take(&mut self.block_guards);
        self.populate_sig_param_types(&i.sig);

        visit::visit_item_fn(self, i);

        self.local_types = prev_types;
        self.fixed_array_lengths = prev_arrays;
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

        // Rule 4: `unsafe impl` requires a `// SAFETY:` comment
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
        let prev_arrays = std::mem::take(&mut self.fixed_array_lengths);
        let prev_block_guards = std::mem::take(&mut self.block_guards);
        self.populate_sig_param_types(&i.sig);

        visit::visit_impl_item_fn(self, i);

        self.local_types = prev_types;
        self.fixed_array_lengths = prev_arrays;
        self.block_guards = prev_block_guards;
        self.scope.exit(snap);
    }

    fn visit_block(&mut self, b: &'ast Block) {
        let saved_block_guards_len = self.block_guards.len();

        for stmt in &b.stmts {
            self.visit_stmt(stmt);
            // If this statement is an `assert!(...)` or an `if cond { return/continue/break }` early guard,
            // record the post-statement bounds guard for subsequent statements in this block.
            extract_post_stmt_bounds_guards(stmt, &mut self.block_guards);
        }

        self.block_guards.truncate(saved_block_guards_len);
    }

    fn visit_stmt(&mut self, s: &'ast Stmt) {
        if let Stmt::Local(local) = s {
            let pat_ident = extract_local_ident_and_type(&local.pat);
            if let Some((name, Some(explicit_ty))) = &pat_ident {
                self.local_types.insert(name.clone(), *explicit_ty);
            } else if let Some((name, None)) = &pat_ident
                && let Some(init) = &local.init
            {
                if let Some(inferred_ty) = self.infer_expr_numeric_type(&init.expr) {
                    self.local_types.insert(name.clone(), inferred_ty);
                }
                if let Expr::Array(arr) = init.expr.as_ref() {
                    self.fixed_array_lengths
                        .insert(name.clone(), arr.elems.len());
                } else if let Expr::Reference(expr_ref) = init.expr.as_ref()
                    && let Expr::Array(arr) = expr_ref.expr.as_ref()
                {
                    self.fixed_array_lengths
                        .insert(name.clone(), arr.elems.len());
                }
            }
        }
        visit::visit_stmt(self, s);
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

fn use_tree_imports_mem_forget(tree: &UseTree, prefix: &str) -> bool {
    match tree {
        UseTree::Path(use_path) => {
            let next_prefix = if prefix.is_empty() {
                use_path.ident.to_string()
            } else {
                format!("{prefix}::{}", use_path.ident)
            };
            use_tree_imports_mem_forget(&use_path.tree, &next_prefix)
        }
        UseTree::Name(use_name) => {
            let full = if prefix.is_empty() {
                use_name.ident.to_string()
            } else {
                format!("{prefix}::{}", use_name.ident)
            };
            matches!(
                full.as_str(),
                "std::mem::forget" | "core::mem::forget" | "mem::forget"
            )
        }
        UseTree::Rename(use_rename) => {
            let full = if prefix.is_empty() {
                use_rename.ident.to_string()
            } else {
                format!("{prefix}::{}", use_rename.ident)
            };
            matches!(
                full.as_str(),
                "std::mem::forget" | "core::mem::forget" | "mem::forget"
            )
        }
        UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_imports_mem_forget(item, prefix)),
        UseTree::Glob(_) => matches!(prefix, "std::mem" | "core::mem"),
    }
}

fn is_mem_forget_path(path: &syn::Path, has_imported_mem_forget: bool) -> bool {
    let joined = path_to_string(path);
    matches!(
        joined.as_str(),
        "std::mem::forget" | "core::mem::forget" | "mem::forget"
    ) || (has_imported_mem_forget && joined == "forget")
}

fn extract_numeric_type(ty: &Type) -> Option<NumericType> {
    let name = extract_type_name(ty)?;
    NumericType::from_type_name(&name)
}

fn extract_local_ident_and_type(pat: &Pat) -> Option<(String, Option<NumericType>)> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Pat has many variants; only ident and typed patterns bind a single local variable"
    )]
    match pat {
        Pat::Ident(pat_ident) => Some((pat_ident.ident.to_string(), None)),
        Pat::Type(pat_type) => {
            let name = extract_pat_ident(&pat_type.pat)?;
            let num_ty = extract_numeric_type(&pat_type.ty);
            Some((name, num_ty))
        }
        _ => None,
    }
}

fn is_lossy_or_sign_changing_cast(src_ty: Option<NumericType>, target_ty: NumericType) -> bool {
    match src_ty {
        Some(NumericType::UnsuffixedInt(val)) => {
            if val < 0 && target_ty.is_unsigned_int() {
                return true;
            }
            match target_ty {
                NumericType::U8 => !(0..=i128::from(u8::MAX)).contains(&val),
                NumericType::U16 => !(0..=i128::from(u16::MAX)).contains(&val),
                NumericType::U32 => !(0..=i128::from(u32::MAX)).contains(&val),
                NumericType::I8 => !(i128::from(i8::MIN)..=i128::from(i8::MAX)).contains(&val),
                NumericType::I16 => !(i128::from(i16::MIN)..=i128::from(i16::MAX)).contains(&val),
                NumericType::I32 => !(i128::from(i32::MIN)..=i128::from(i32::MAX)).contains(&val),
                NumericType::U64
                | NumericType::U128
                | NumericType::Usize
                | NumericType::I64
                | NumericType::I128
                | NumericType::Isize
                | NumericType::F32
                | NumericType::F64
                | NumericType::Bool
                | NumericType::Char
                | NumericType::UnsuffixedInt(_) => false,
            }
        }
        Some(NumericType::Bool | NumericType::Char) => false,
        Some(src) => {
            if src == target_ty {
                return false;
            }
            // Float-to-int or f64-to-f32 is always potentially lossy
            if src.is_float() {
                return !matches!((src, target_ty), (NumericType::F32, NumericType::F64));
            }
            if target_ty.is_float() {
                // Large integers (64-bit / 128-bit / usize / isize) lose precision in f32 (or f64 for 64/128-bit)
                return src.bit_width_rank() >= target_ty.bit_width_rank();
            }
            // Signed -> Unsigned always risks sign loss
            if src.is_signed_int() && target_ty.is_unsigned_int() {
                return true;
            }
            // Unsigned -> Signed risks wrap when unsigned width >= signed width
            if src.is_unsigned_int() && target_ty.is_signed_int() {
                return src.bit_width_rank() >= target_ty.bit_width_rank();
            }
            // Same-signedness narrowing (`u64 as u32`, `usize as u32`, `u64 as usize`, `i64 as i32`, etc.)
            src.bit_width_rank() > target_ty.bit_width_rank()
        }
        None => {
            // Unknown source expression type: flag casts to narrower or sign-changing integer targets
            matches!(
                target_ty,
                NumericType::U8
                    | NumericType::U16
                    | NumericType::U32
                    | NumericType::Usize
                    | NumericType::I8
                    | NumericType::I16
                    | NumericType::I32
                    | NumericType::Isize
            )
        }
    }
}

fn line_has_safety_comment(line: &str) -> bool {
    let Some(comment_pos) = line.find("//").or_else(|| line.find("/*")) else {
        return false;
    };
    let comment_part = line[comment_pos..].to_ascii_lowercase();
    comment_part.contains("safety:") || comment_part.contains("# safety")
}

fn extract_cond_bounds_guards(cond: &Expr, negated: bool, out: &mut Vec<SliceGuard>) {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Condition guard extraction inspects logical connectives, unary negation, method calls, and comparisons"
    )]
    match cond {
        Expr::Paren(p) => extract_cond_bounds_guards(&p.expr, negated, out),
        Expr::Group(g) => extract_cond_bounds_guards(&g.expr, negated, out),
        Expr::Unary(u) if matches!(u.op, UnOp::Not(_)) => {
            extract_cond_bounds_guards(&u.expr, !negated, out);
        }
        Expr::Binary(bin) => match bin.op {
            BinOp::And(_) if !negated => {
                extract_cond_bounds_guards(&bin.left, false, out);
                extract_cond_bounds_guards(&bin.right, false, out);
            }
            BinOp::Or(_) if negated => {
                extract_cond_bounds_guards(&bin.left, true, out);
                extract_cond_bounds_guards(&bin.right, true, out);
            }
            BinOp::Lt(_)
            | BinOp::Le(_)
            | BinOp::Gt(_)
            | BinOp::Ge(_)
            | BinOp::Ne(_)
            | BinOp::Eq(_) => {
                extract_comparison_guard(&bin.left, &bin.op, &bin.right, negated, out);
            }
            _ => {}
        },
        Expr::Let(expr_let) if !negated => {
            extract_cond_bounds_guards(&expr_let.expr, false, out);
        }
        Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            let recv = normalize_expr_key(&mc.receiver);
            if recv.is_empty() {
                return;
            }
            // `!slice.is_empty()` (when `negated == true` on `slice.is_empty()`)
            if method == "is_empty" && mc.args.is_empty() && negated {
                out.push(SliceGuard {
                    collection: recv,
                    index: Some("0".to_string()),
                    non_empty: true,
                    inclusive_upper_bound: false,
                });
            } else if method == "is_char_boundary"
                && !negated
                && let Some(first_arg) = mc.args.first()
            {
                let idx_key = normalize_expr_key(first_arg);
                if !idx_key.is_empty() {
                    out.push(SliceGuard {
                        collection: recv,
                        index: Some(idx_key),
                        non_empty: false,
                        inclusive_upper_bound: true,
                    });
                }
            }
        }
        _ => {}
    }
}

fn extract_comparison_guard(
    left: &Expr,
    op: &BinOp,
    right: &Expr,
    negated: bool,
    out: &mut Vec<SliceGuard>,
) {
    let Some(cmp) = resolve_effective_cmp(op, negated) else {
        return;
    };

    // Case 1: `idx < coll.len()` or `idx <= coll.len()`
    if let Some(coll) = extract_len_receiver(right) {
        let idx_key = normalize_expr_key(left);
        if !idx_key.is_empty() {
            match cmp {
                EffectiveCmp::Lt => {
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(idx_key),
                        non_empty: true,
                        inclusive_upper_bound: false,
                    });
                }
                EffectiveCmp::Le => {
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(idx_key),
                        non_empty: false,
                        inclusive_upper_bound: true,
                    });
                }
                EffectiveCmp::Gt | EffectiveCmp::Ge | EffectiveCmp::Ne => {}
            }
        }
    }

    // Case 2: `coll.len() > idx` or `coll.len() >= 1` or `coll.len() != 0`
    if let Some(coll) = extract_len_receiver(left) {
        let idx_key = normalize_expr_key(right);
        if !idx_key.is_empty() {
            match cmp {
                EffectiveCmp::Gt => {
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(idx_key),
                        non_empty: true,
                        inclusive_upper_bound: false,
                    });
                }
                EffectiveCmp::Ge => {
                    let is_positive_lit = idx_key.parse::<usize>().is_ok_and(|n| n >= 1);
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(if is_positive_lit {
                            "0".to_string()
                        } else {
                            idx_key
                        }),
                        non_empty: is_positive_lit,
                        inclusive_upper_bound: !is_positive_lit,
                    });
                }
                EffectiveCmp::Ne if idx_key == "0" => {
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some("0".to_string()),
                        non_empty: true,
                        inclusive_upper_bound: false,
                    });
                }
                EffectiveCmp::Lt | EffectiveCmp::Le | EffectiveCmp::Ne => {}
            }
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "syn::BinOp is non-exhaustive and includes arithmetic/bitwise operators; only comparison operators form bounds guards"
)]
const fn resolve_effective_cmp(op: &BinOp, negated: bool) -> Option<EffectiveCmp> {
    if negated {
        match op {
            BinOp::Ge(_) => Some(EffectiveCmp::Lt),
            BinOp::Gt(_) => Some(EffectiveCmp::Le),
            BinOp::Le(_) => Some(EffectiveCmp::Gt),
            BinOp::Lt(_) => Some(EffectiveCmp::Ge),
            BinOp::Eq(_) => Some(EffectiveCmp::Ne),
            _ => None,
        }
    } else {
        match op {
            BinOp::Lt(_) => Some(EffectiveCmp::Lt),
            BinOp::Le(_) => Some(EffectiveCmp::Le),
            BinOp::Gt(_) => Some(EffectiveCmp::Gt),
            BinOp::Ge(_) => Some(EffectiveCmp::Ge),
            BinOp::Ne(_) => Some(EffectiveCmp::Ne),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectiveCmp {
    Lt,
    Le,
    Gt,
    Ge,
    Ne,
}

fn extract_len_receiver(expr: &Expr) -> Option<String> {
    if let Expr::MethodCall(mc) = expr
        && mc.method == "len"
        && mc.args.is_empty()
    {
        let recv = normalize_expr_key(&mc.receiver);
        if !recv.is_empty() {
            return Some(recv);
        }
    }
    None
}

fn extract_post_stmt_bounds_guards(stmt: &Stmt, block_guards: &mut Vec<SliceGuard>) {
    match stmt {
        Stmt::Expr(Expr::If(expr_if), _) => {
            if block_always_diverges(&expr_if.then_branch) {
                extract_cond_bounds_guards(&expr_if.cond, true, block_guards);
            }
        }
        Stmt::Macro(stmt_macro) => {
            if stmt_macro.mac.path.is_ident("assert")
                && let Ok(cond_expr) = syn::parse2::<Expr>(stmt_macro.mac.tokens.clone())
            {
                extract_cond_bounds_guards(&cond_expr, false, block_guards);
            }
        }
        Stmt::Local(_) | Stmt::Item(_) | Stmt::Expr(..) => {}
    }
}

fn block_always_diverges(block: &Block) -> bool {
    let Some(last) = block.stmts.last() else {
        return false;
    };
    match last {
        Stmt::Expr(expr, _) => expr_diverges(expr),
        Stmt::Macro(m) => {
            let name = m
                .mac
                .path
                .segments
                .last()
                .map_or_else(String::new, |s| s.ident.to_string());
            matches!(name.as_str(), "panic" | "unreachable" | "todo" | "bail")
        }
        Stmt::Local(_) | Stmt::Item(_) => false,
    }
}

fn expr_diverges(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::Return(_) | Expr::Break(_) | Expr::Continue(_)
    )
}
