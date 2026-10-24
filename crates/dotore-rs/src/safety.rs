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
    BinOp, Block, Expr, ExprBinary, ExprCall, ExprCast, ExprClosure, ExprForLoop, ExprIf,
    ExprIndex, ExprMatch, ExprMethodCall, ExprUnsafe, ExprWhile, File, ImplItemFn, Item, ItemFn,
    ItemImpl, ItemMod, Lit, Pat, Signature, Stmt, TraitItemFn, Type, UnOp, UseTree,
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
    let mut const_array_lengths = HashMap::new();
    for item in &ast.items {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Only use, const, and static items contribute top-level imports and array lengths"
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
    min_len: usize,
    inclusive_upper_bound: bool,
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

    fn collections_share_len(&self, a: &str, b: &str) -> bool {
        let sa = a.strip_suffix(".as_bytes()").unwrap_or(a);
        let sb = b.strip_suffix(".as_bytes()").unwrap_or(b);
        if sa == sb {
            return true;
        }
        let root_a = self.len_equivalents.get(sa).map_or(sa, String::as_str);
        let root_b = self.len_equivalents.get(sb).map_or(sb, String::as_str);
        root_a.strip_suffix(".as_bytes()").unwrap_or(root_a)
            == root_b.strip_suffix(".as_bytes()").unwrap_or(root_b)
    }

    fn infer_expr_numeric_type(&self, expr: &Expr) -> Option<NumericType> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Expr has dozens of variants; numeric inference inspects literals, paths, fields, calls, binary/unary ops, and casts"
        )]
        match expr {
            Expr::Paren(paren) => self.infer_expr_numeric_type(&paren.expr),
            Expr::Group(group) => self.infer_expr_numeric_type(&group.expr),
            Expr::Path(expr_path) => {
                if expr_path.qself.is_none()
                    && let Some(ident) = expr_path.path.get_ident()
                {
                    let name = ident.to_string();
                    if name == "self" {
                        return Some(NumericType::U16);
                    }
                    return self.local_types.get(&name).copied();
                }
                None
            }
            Expr::Field(expr_field) => {
                if let syn::Member::Named(ident) = &expr_field.member {
                    match ident.to_string().as_str() {
                        "start" | "end" | "line" | "column" | "index" => Some(NumericType::U32),
                        "health_score" => Some(NumericType::U8),
                        "value" => Some(NumericType::F64),
                        _ => None,
                    }
                } else {
                    None
                }
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
                Lit::Byte(_) => Some(NumericType::U8),
                Lit::Bool(_) => Some(NumericType::Bool),
                Lit::Char(_) => Some(NumericType::Char),
                _ => None,
            },
            Expr::Unary(expr_unary) => {
                if matches!(expr_unary.op, UnOp::Neg(_)) {
                    match self.infer_expr_numeric_type(&expr_unary.expr) {
                        Some(NumericType::UnsuffixedInt(v)) => Some(NumericType::UnsuffixedInt(-v)),
                        Some(other) => Some(other),
                        None => Some(NumericType::I64),
                    }
                } else {
                    self.infer_expr_numeric_type(&expr_unary.expr)
                }
            }
            Expr::Binary(expr_bin) => self.infer_binary_numeric_type(expr_bin),
            Expr::Call(expr_call) => {
                if let Expr::Path(expr_path) = expr_call.func.as_ref() {
                    let segs: Vec<String> = expr_path
                        .path
                        .segments
                        .iter()
                        .map(|s| s.ident.to_string())
                        .collect();
                    if let [ty_seg, fn_seg] = segs.as_slice()
                        && matches!(
                            fn_seg.as_str(),
                            "from_be_bytes" | "from_le_bytes" | "from_ne_bytes" | "from"
                        )
                    {
                        return NumericType::from_type_name(ty_seg);
                    }
                }
                None
            }
            Expr::MethodCall(method_call) => {
                let method_name = method_call.method.to_string();
                match method_name.as_str() {
                    "len" | "count" | "capacity" => Some(NumericType::Usize),
                    "saturating_sub" | "saturating_add" | "wrapping_add" | "wrapping_sub"
                    | "min" | "max" | "clamp" => self
                        .infer_expr_numeric_type(&method_call.receiver)
                        .or_else(|| {
                            method_call
                                .args
                                .first()
                                .and_then(|arg| self.infer_expr_numeric_type(arg))
                                .filter(|t| !matches!(t, NumericType::UnsuffixedInt(_)))
                        }),
                    _ => None,
                }
            }
            Expr::Cast(inner_cast) => extract_numeric_type(&inner_cast.ty),
            _ => None,
        }
    }

    fn infer_binary_numeric_type(&self, expr_bin: &syn::ExprBinary) -> Option<NumericType> {
        let left_ty = self.infer_expr_numeric_type(&expr_bin.left);
        let right_ty = self.infer_expr_numeric_type(&expr_bin.right);

        if matches!(expr_bin.op, BinOp::BitAnd(_)) {
            if let Some(NumericType::UnsuffixedInt(mask)) = right_ty
                && mask >= 0
            {
                return Some(NumericType::UnsuffixedInt(mask));
            }
            if let Some(NumericType::UnsuffixedInt(mask)) = left_ty
                && mask >= 0
            {
                return Some(NumericType::UnsuffixedInt(mask));
            }
        }

        if matches!(expr_bin.op, BinOp::Shr(_) | BinOp::Shl(_)) {
            return left_ty;
        }

        match (left_ty, right_ty) {
            (Some(l), Some(NumericType::UnsuffixedInt(_))) => Some(l),
            (Some(NumericType::UnsuffixedInt(_)), Some(r)) => Some(r),
            (Some(l), Some(r)) if l == r => Some(l),
            (Some(l), None) if !matches!(l, NumericType::UnsuffixedInt(_)) => Some(l),
            (None, Some(r)) if !matches!(r, NumericType::UnsuffixedInt(_)) => Some(r),
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
            let prev = self.lines.get(cursor).copied().unwrap_or_default().trim();
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
        // String-literal key indexing (`serde_json::Value` `val["key"]`) is not a `usize` slice index
        if let Expr::Lit(expr_lit) = unwrap_paren_group(&expr_index.index)
            && matches!(expr_lit.lit, Lit::Str(_))
        {
            return true;
        }

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

        let all_guards: Vec<&SliceGuard> = self
            .active_guards
            .iter()
            .chain(self.block_guards.iter())
            .collect();

        if let Expr::Range(range) = expr_index.index.as_ref() {
            return self.is_range_index_guarded(range, &coll_key, &all_guards);
        }

        let idx_key = normalize_expr_key(&expr_index.index);
        let known_len = self.fixed_array_lengths.get(&coll_key).copied();

        // Modulo bounds: `arr[idx % N]` or `arr[idx % arr.len()]`
        if let Some((_, rhs_mod)) = idx_key.rsplit_once('%') {
            if let Ok(mod_n) = rhs_mod.parse::<usize>()
                && mod_n >= 1
                && known_len.is_some_and(|len| mod_n <= len)
            {
                return true;
            }
            if rhs_mod == format!("{coll_key}.len()")
                && (known_len.is_some_and(|len| len >= 1)
                    || self
                        .active_guards
                        .iter()
                        .chain(self.block_guards.iter())
                        .any(|g| {
                            self.collections_share_len(&g.collection, &coll_key) && g.min_len >= 1
                        }))
            {
                return true;
            }
        }

        if let Some((base_var, sub_lit)) = idx_key.rsplit_once('-')
            && let Ok(k) = sub_lit.parse::<usize>()
        {
            if base_var == format!("{coll_key}.len()") {
                let has_min_k = known_len.is_some_and(|len| len >= k)
                    || self
                        .active_guards
                        .iter()
                        .chain(self.block_guards.iter())
                        .any(|g| {
                            self.collections_share_len(&g.collection, &coll_key)
                                && (g.min_len >= k
                                    || (k == 1 && !g.inclusive_upper_bound && g.index.is_some()))
                        });
                if has_min_k {
                    return true;
                }
            } else {
                let base_bounded = self
                    .active_guards
                    .iter()
                    .chain(self.block_guards.iter())
                    .any(|g| {
                        !g.inclusive_upper_bound
                            && g.index.as_deref() == Some(base_var)
                            && (self.collections_share_len(&g.collection, &coll_key)
                                || (g.collection.is_empty()
                                    && known_len.is_some_and(|len| g.min_len <= len)))
                    });
                let base_ge_k = self
                    .active_guards
                    .iter()
                    .chain(self.block_guards.iter())
                    .any(|g| {
                        g.collection.is_empty()
                            && g.index.as_deref() == Some(base_var)
                            && g.min_len >= k
                    });
                if base_bounded && base_ge_k {
                    return true;
                }
            }
        }


        let parsed_idx = idx_key.parse::<usize>().ok();
        for g in &all_guards {
            if g.collection.is_empty() {
                if !g.inclusive_upper_bound
                    && g.index.as_deref() == Some(idx_key.as_str())
                    && known_len.is_some_and(|len| g.min_len > 0 && g.min_len <= len)
                {
                    return true;
                }
                continue;
            }
            if !self.collections_share_len(&g.collection, &coll_key) {
                continue;
            }
            if !g.inclusive_upper_bound && g.index.as_deref() == Some(idx_key.as_str()) {
                return true;
            }
            if let Some(n) = parsed_idx {
                if n < g.min_len {
                    return true;
                }
                if n == 0 && !g.inclusive_upper_bound && g.index.is_some() {
                    return true;
                }
            }
        }
        false
    }

    fn is_range_index_guarded(
        &self,
        range: &syn::ExprRange,
        coll_key: &str,
        all_guards: &[&SliceGuard],
    ) -> bool {
        let end_clamped = range
            .end
            .as_ref()
            .is_some_and(|e| self.expr_clamped_to_collection_len(e, coll_key));
        let start_clamped = range
            .start
            .as_ref()
            .is_some_and(|e| self.expr_clamped_to_collection_len(e, coll_key));
        if (range.end.is_some() && end_clamped) || (range.end.is_none() && start_clamped) {
            return true;
        }
        let end_key = range.end.as_ref().map(|e| normalize_expr_key(e));
        let start_key = range.start.as_ref().map(|e| normalize_expr_key(e));
        let max_min_len = all_guards
            .iter()
            .filter(|g| self.collections_share_len(&g.collection, coll_key))
            .map(|g| g.min_len)
            .max()
            .unwrap_or(0)
            .max(self.fixed_array_lengths.get(coll_key).copied().unwrap_or(0));

        if let Some(ek) = &end_key {
            if self.is_range_end_within_bounds(ek, &range.limits, coll_key, max_min_len, all_guards)
            {
                return true;
            }
        } else if let Some(sk) = &start_key
            && self.is_range_start_within_bounds(sk, coll_key, max_min_len, all_guards)
        {
            return true;
        }


        for g in all_guards {
            if !self.collections_share_len(&g.collection, coll_key) {
                continue;
            }
            if let Some(ek) = &end_key
                && (g.index.as_deref() == Some(ek.as_str())
                    || (matches!(range.limits, syn::RangeLimits::Closed(_))
                        && g.index.as_deref() == Some(&format!("{ek}+1"))))
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
        false
    }

    fn is_range_end_within_bounds(
        &self,
        ek: &str,
        limits: &syn::RangeLimits,
        coll_key: &str,
        max_min_len: usize,
        all_guards: &[&SliceGuard],
    ) -> bool {
        if let Ok(end_lit) = ek.parse::<usize>() {
            let end_needed = end_lit + usize::from(matches!(limits, syn::RangeLimits::Closed(_)));
            if end_needed <= max_min_len {
                return true;
            }
        }
        if let Some(sub_k) = ek.strip_prefix(&format!("{coll_key}.len()-"))
            && let Ok(k) = sub_k.parse::<usize>()
            && max_min_len >= k
        {
            return true;
        }
        if let Some((mul_part, add_lit)) = ek.rsplit_once('+')
            && let Ok(add_n) = add_lit.parse::<usize>()
            && let Some((base_var, mul_lit)) = mul_part.rsplit_once('*')
            && let Ok(mul_n) = mul_lit.parse::<usize>()
            && let Some(&known_len) = self.fixed_array_lengths.get(coll_key)
        {
            let max_idx_bound = all_guards
                .iter()
                .filter(|g| g.index.as_deref() == Some(base_var))
                .filter_map(|g| {
                    if g.collection.is_empty() {
                        Some(g.min_len)
                    } else {
                        self.fixed_array_lengths.get(&g.collection).copied()
                    }
                })
                .max();
            if let Some(bound_n) = max_idx_bound
                && bound_n > 0
                && (bound_n - 1) * mul_n + add_n <= known_len
            {
                return true;
            }
        }
        false
    }

    fn is_range_start_within_bounds(
        &self,
        sk: &str,
        coll_key: &str,
        max_min_len: usize,
        all_guards: &[&SliceGuard],
    ) -> bool {
        if let Ok(start_lit) = sk.parse::<usize>()
            && start_lit <= max_min_len
        {
            return true;
        }
        if let Some((base_var, add_lit)) = sk.rsplit_once('+')
            && add_lit == "1"
            && all_guards.iter().any(|g| {
                !g.inclusive_upper_bound
                    && g.index.as_deref() == Some(base_var)
                    && self.collections_share_len(&g.collection, coll_key)
            })
        {
            return true;
        }
        false
    }

    fn expr_clamped_to_collection_len(&self, expr: &Expr, coll_key: &str) -> bool {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Only `.min(coll.len())` method calls form clamping bounds"
        )]
        match unwrap_paren_group(expr) {
            Expr::MethodCall(mc) if mc.method == "min" && mc.args.len() == 1 => {
                let arg = &mc.args[0];
                extract_len_receiver(&mc.receiver)
                    .is_some_and(|c| self.collections_share_len(&c, coll_key))
                    || extract_len_receiver(arg)
                        .is_some_and(|c| self.collections_share_len(&c, coll_key))
            }
            _ => false,
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

    fn collect_for_loop_guards(&mut self, i: &ExprForLoop, added_window_var: &mut Option<String>) {
        if let Expr::Range(range) = i.expr.as_ref()
            && let Some(loop_var) = extract_pat_ident(&i.pat)
        {
            self.collect_range_for_loop_guards(range, &loop_var);
            return;
        }
        if let Expr::MethodCall(mc) = i.expr.as_ref() {
            self.collect_method_for_loop_guards(mc, &i.pat, added_window_var);
        } else if let Expr::Field(expr_field) = i.expr.as_ref()
            && let syn::Member::Unnamed(idx) = &expr_field.member
            && idx.index == 0
            && let Expr::MethodCall(mc) = expr_field.base.as_ref()
            && mc.method == "as_chunks"
            && let Some(chunk_len) = extract_turbofish_const_usize(&mc.turbofish)
            && let Some(chunk_var) = extract_pat_ident(&i.pat)
        {
            self.fixed_array_lengths
                .insert(chunk_var.clone(), chunk_len);
            *added_window_var = Some(chunk_var);
        }
    }

    fn collect_range_for_loop_guards(&mut self, range: &syn::ExprRange, loop_var: &str) {
        if let Some(start_expr) = &range.start
            && let Ok(start_lit) = normalize_expr_key(start_expr).parse::<usize>()
            && start_lit >= 1
        {
            self.active_guards.push(SliceGuard {
                collection: String::new(),
                index: Some(loop_var.to_owned()),
                min_len: start_lit,
                inclusive_upper_bound: false,
            });
        }
        let Some(end_expr) = &range.end else {
            return;
        };
        if !matches!(range.limits, syn::RangeLimits::HalfOpen(_)) {
            return;
        }
        if let Some(coll) = extract_len_receiver(end_expr) {
            let root_coll = self.len_equivalents.get(&coll).cloned().unwrap_or(coll);
            self.active_guards.push(SliceGuard {
                collection: root_coll,
                index: Some(loop_var.to_owned()),
                min_len: 1,
                inclusive_upper_bound: false,
            });
            return;
        }
        let end_key = normalize_expr_key(end_expr);
        if let Ok(end_lit) = end_key.parse::<usize>() {
            self.active_guards.push(SliceGuard {
                collection: String::new(),
                index: Some(loop_var.to_owned()),
                min_len: end_lit,
                inclusive_upper_bound: false,
            });
        } else if let Some(root_coll) = self.len_equivalents.get(&end_key).cloned() {
            self.active_guards.push(SliceGuard {
                collection: root_coll,
                index: Some(loop_var.to_owned()),
                min_len: 1,
                inclusive_upper_bound: false,
            });
        }
    }

    fn collect_method_for_loop_guards(
        &mut self,
        mc: &ExprMethodCall,
        pat: &Pat,
        added_window_var: &mut Option<String>,
    ) {
        let method = mc.method.to_string();
        if matches!(method.as_str(), "enumerate" | "char_indices")
            && let Pat::Tuple(pat_tuple) = pat
            && let Some(first_pat) = pat_tuple.elems.first()
            && let Some(idx_var) = extract_pat_ident(first_pat)
            && let Some(base_coll) = extract_iter_receiver(&mc.receiver)
        {
            let root_coll = self
                .len_equivalents
                .get(&base_coll)
                .cloned()
                .unwrap_or(base_coll);
            if let Some(chunk_count) =
                extract_as_chunks_divisor_len(&mc.receiver, &self.fixed_array_lengths)
            {
                self.active_guards.push(SliceGuard {
                    collection: String::new(),
                    index: Some(idx_var.clone()),
                    min_len: chunk_count,
                    inclusive_upper_bound: false,
                });
            }
            self.active_guards.push(SliceGuard {
                collection: root_coll.clone(),
                index: Some(idx_var.clone()),
                min_len: 1,
                inclusive_upper_bound: false,
            });
            if method == "char_indices"
                && let Some(second_pat) = pat_tuple.elems.get(1)
                && let Some(ch_var) = extract_pat_ident(second_pat)
            {
                self.active_guards.push(SliceGuard {
                    collection: root_coll.clone(),
                    index: Some(format!("{idx_var}+1")),
                    min_len: 1,
                    inclusive_upper_bound: true,
                });
                self.active_guards.push(SliceGuard {
                    collection: root_coll,
                    index: Some(format!("{idx_var}+{ch_var}.len_utf8()")),
                    min_len: 1,
                    inclusive_upper_bound: true,
                });
            }
        } else if method == "match_indices"
            && let Pat::Tuple(pat_tuple) = pat
            && let Some(first_pat) = pat_tuple.elems.first()
            && let Some(idx_var) = extract_pat_ident(first_pat)
        {
            let recv_key = normalize_expr_key(&mc.receiver);
            if !recv_key.is_empty() {
                self.active_guards.push(SliceGuard {
                    collection: recv_key.clone(),
                    index: Some(idx_var.clone()),
                    min_len: 1,
                    inclusive_upper_bound: false,
                });
                if let Some(first_arg) = mc.args.first()
                    && let Some(off) = extract_search_pat_offset(first_arg)
                {
                    self.active_guards.push(SliceGuard {
                        collection: recv_key,
                        index: Some(format!("{idx_var}+{off}")),
                        min_len: 1,
                        inclusive_upper_bound: true,
                    });
                }
            }
        } else if matches!(method.as_str(), "windows" | "chunks_exact")
            && let Some(first_arg) = mc.args.first()
            && let Ok(win_len) = normalize_expr_key(first_arg).parse::<usize>()
            && let Some(win_var) = extract_pat_ident(pat)
        {
            self.fixed_array_lengths.insert(win_var.clone(), win_len);
            *added_window_var = Some(win_var);
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
            // If this statement is an `assert!(...)` or an `if cond { return/continue/break }` early guard,
            // record the post-statement bounds guard for subsequent statements in this block.
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

        // 1. `for i in start..end`
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
            reason = "Only short-circuit logical `&&` and `||` operators propagate LHS bounds guards into RHS"
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
            // Unknown source expression type: flag casts to narrower or signed integer targets,
            // while `as usize` is only flagged when the source is inferred as signed, 64/128-bit, or float.
            matches!(
                target_ty,
                NumericType::U8
                    | NumericType::U16
                    | NumericType::U32
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
            extract_let_pattern_bounds_guards(&expr_let.pat, &expr_let.expr, out);
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
                    min_len: 1,
                    inclusive_upper_bound: false,
                });
            } else if matches!(method.as_str(), "starts_with" | "ends_with")
                && !negated
                && let Some(first_arg) = mc.args.first()
            {
                let min_len = extract_pattern_arg_min_len(first_arg);
                out.push(SliceGuard {
                    collection: recv,
                    index: Some("0".to_string()),
                    min_len,
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
                        min_len: 0,
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

    // Case 1: `idx < coll.len()`, `idx <= coll.len()`, `N <= coll.len()`, `N == coll.len()`
    if let Some(coll) = extract_len_receiver(right) {
        let idx_key = normalize_expr_key(left);
        if !idx_key.is_empty() {
            let lit_val = idx_key.parse::<usize>().ok();
            match cmp {
                EffectiveCmp::Lt => {
                    let min_len = lit_val.map_or(1, |n| n + 1);
                    out.push(SliceGuard {
                        collection: coll.clone(),
                        index: Some(idx_key.clone()),
                        min_len,
                        inclusive_upper_bound: false,
                    });
                    if let Some((base_var, add_lit)) = idx_key.rsplit_once('+')
                        && add_lit.parse::<usize>().is_ok_and(|k| k >= 1)
                    {
                        out.push(SliceGuard {
                            collection: coll,
                            index: Some(base_var.to_string()),
                            min_len: 1,
                            inclusive_upper_bound: false,
                        });
                    }
                }
                EffectiveCmp::Le => {
                    let min_len = lit_val.unwrap_or(0);
                    out.push(SliceGuard {
                        collection: coll.clone(),
                        index: Some(idx_key.clone()),
                        min_len,
                        inclusive_upper_bound: true,
                    });
                    if let Some((base_var, add_lit)) = idx_key.rsplit_once('+')
                        && add_lit.parse::<usize>().is_ok_and(|k| k >= 1)
                    {
                        out.push(SliceGuard {
                            collection: coll,
                            index: Some(base_var.to_string()),
                            min_len: 1,
                            inclusive_upper_bound: false,
                        });
                    }
                }
                EffectiveCmp::Eq => {
                    if let Some(n) = lit_val {
                        out.push(SliceGuard {
                            collection: coll,
                            index: None,
                            min_len: n,
                            inclusive_upper_bound: false,
                        });
                    }
                }
                EffectiveCmp::Ne => {
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(idx_key),
                        min_len: 1,
                        inclusive_upper_bound: false,
                    });
                }
                EffectiveCmp::Gt | EffectiveCmp::Ge => {}
            }
        }
        return;
    }

    // Case 2: `coll.len() > idx`, `coll.len() >= N`, `coll.len() == N`, `coll.len() != 0`
    if let Some(coll) = extract_len_receiver(left) {
        let idx_key = normalize_expr_key(right);
        if !idx_key.is_empty() {
            let lit_val = idx_key.parse::<usize>().ok();
            match cmp {
                EffectiveCmp::Gt => {
                    let min_len = lit_val.map_or(1, |n| n + 1);
                    out.push(SliceGuard {
                        collection: coll.clone(),
                        index: Some(idx_key.clone()),
                        min_len,
                        inclusive_upper_bound: false,
                    });
                    if let Some((base_var, add_lit)) = idx_key.rsplit_once('+')
                        && add_lit.parse::<usize>().is_ok_and(|k| k >= 1)
                    {
                        out.push(SliceGuard {
                            collection: coll,
                            index: Some(base_var.to_string()),
                            min_len: 1,
                            inclusive_upper_bound: false,
                        });
                    }
                }
                EffectiveCmp::Ge => {
                    let min_len = lit_val.unwrap_or(0);
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(idx_key),
                        min_len,
                        inclusive_upper_bound: true,
                    });
                }
                EffectiveCmp::Eq => {
                    if let Some(n) = lit_val {
                        out.push(SliceGuard {
                            collection: coll,
                            index: None,
                            min_len: n,
                            inclusive_upper_bound: false,
                        });
                    }
                }
                EffectiveCmp::Ne => {
                    out.push(SliceGuard {
                        collection: coll,
                        index: Some(idx_key),
                        min_len: 1,
                        inclusive_upper_bound: false,
                    });
                }
                EffectiveCmp::Lt | EffectiveCmp::Le => {}
            }
        }
        return;
    }

    // Case 3: Index lower-bound guards (`idx > 0`, `idx >= k`, `idx != 0`, `0 < idx`)
    let left_key = normalize_expr_key(left);
    let right_key = normalize_expr_key(right);
    if !left_key.is_empty()
        && let Ok(lit_val) = right_key.parse::<usize>()
    {
        let min_idx = match cmp {
            EffectiveCmp::Gt => Some(lit_val + 1),
            EffectiveCmp::Ge | EffectiveCmp::Eq => Some(lit_val),
            EffectiveCmp::Ne if lit_val == 0 => Some(1),
            EffectiveCmp::Lt | EffectiveCmp::Le | EffectiveCmp::Ne => None,
        };
        if let Some(m) = min_idx
            && m >= 1
        {
            out.push(SliceGuard {
                collection: String::new(),
                index: Some(left_key),
                min_len: m,
                inclusive_upper_bound: false,
            });
        }
    } else if !right_key.is_empty()
        && let Ok(lit_val) = left_key.parse::<usize>()
    {
        let min_idx = match cmp {
            EffectiveCmp::Lt => Some(lit_val + 1),
            EffectiveCmp::Le | EffectiveCmp::Eq => Some(lit_val),
            EffectiveCmp::Ne if lit_val == 0 => Some(1),
            EffectiveCmp::Gt | EffectiveCmp::Ge | EffectiveCmp::Ne => None,
        };
        if let Some(m) = min_idx
            && m >= 1
        {
            out.push(SliceGuard {
                collection: String::new(),
                index: Some(right_key),
                min_len: m,
                inclusive_upper_bound: false,
            });
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
            BinOp::Ne(_) => Some(EffectiveCmp::Eq),
            _ => None,
        }
    } else {
        match op {
            BinOp::Lt(_) => Some(EffectiveCmp::Lt),
            BinOp::Le(_) => Some(EffectiveCmp::Le),
            BinOp::Gt(_) => Some(EffectiveCmp::Gt),
            BinOp::Ge(_) => Some(EffectiveCmp::Ge),
            BinOp::Ne(_) => Some(EffectiveCmp::Ne),
            BinOp::Eq(_) => Some(EffectiveCmp::Eq),
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
    Eq,
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

fn extract_fixed_array_type_len(ty: &Type) -> Option<usize> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Only fixed-size array types and wrappers carry compile-time array length"
    )]
    match ty {
        Type::Array(arr) => normalize_expr_key(&arr.len).parse::<usize>().ok(),
        Type::Reference(tr) => extract_fixed_array_type_len(&tr.elem),
        Type::Paren(p) => extract_fixed_array_type_len(&p.elem),
        Type::Group(g) => extract_fixed_array_type_len(&g.elem),
        _ => None,
    }
}

fn extract_fixed_array_expr_len(expr: &Expr) -> Option<usize> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Only array/repeat literals and fixed-size constructors yield known static lengths"
    )]
    match expr {
        Expr::Paren(p) => extract_fixed_array_expr_len(&p.expr),
        Expr::Group(g) => extract_fixed_array_expr_len(&g.expr),
        Expr::Reference(r) => extract_fixed_array_expr_len(&r.expr),
        Expr::Try(t) => extract_fixed_array_expr_len(&t.expr),
        Expr::Array(arr) => Some(arr.elems.len()),
        Expr::Repeat(rep) => normalize_expr_key(&rep.len).parse::<usize>().ok(),
        Expr::MethodCall(mc) => {
            if mc.method == "read_exact_bytes"
                && let Some(first_arg) = mc.args.first()
            {
                return normalize_expr_key(first_arg).parse::<usize>().ok();
            }
            None
        }
        Expr::If(expr_if) => {
            let then_len = expr_if.then_branch.stmts.last().and_then(|s| match s {
                Stmt::Expr(e, _) => extract_fixed_array_expr_len(e),
                Stmt::Local(_) | Stmt::Item(_) | Stmt::Macro(_) => None,
            })?;
            if let Some((_, else_expr)) = &expr_if.else_branch {
                #[expect(
                    clippy::wildcard_enum_match_arm,
                    reason = "Else branch is either a block or nested expression"
                )]
                let else_len = match else_expr.as_ref() {
                    Expr::Block(b) => b.block.stmts.last().and_then(|s| match s {
                        Stmt::Expr(e, _) => extract_fixed_array_expr_len(e),
                        Stmt::Local(_) | Stmt::Item(_) | Stmt::Macro(_) => None,
                    }),
                    other => extract_fixed_array_expr_len(other),
                }?;
                Some(then_len.min(else_len))
            } else {
                Some(then_len)
            }
        }
        Expr::Call(call) => {
            if let Expr::Path(ep) = call.func.as_ref()
                && ep
                    .path
                    .segments
                    .last()
                    .is_some_and(|s| s.ident == "sha256_bytes")
            {
                return Some(32);
            }
            None
        }
        _ => None,
    }
}

fn extract_iter_receiver(expr: &Expr) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Iterator receiver unwrapping inspects method calls and falls back to direct expression key"
    )]
    match expr {
        Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            if matches!(
                method.as_str(),
                "iter" | "iter_mut" | "into_iter" | "lines" | "chars" | "bytes"
            ) && mc.args.is_empty()
            {
                let recv = normalize_expr_key(&mc.receiver);
                if !recv.is_empty() {
                    return Some(recv);
                }
            }
            None
        }
        _ => {
            let recv = normalize_expr_key(expr);
            if !recv.is_empty() { Some(recv) } else { None }
        }
    }
}

fn extract_len_equivalent_source(
    expr: &Expr,
    len_equivalents: &HashMap<String, String>,
) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Length equivalence inspects method calls, vec! macros, and paren/group wrappers"
    )]
    match expr {
        Expr::Paren(p) => extract_len_equivalent_source(&p.expr, len_equivalents),
        Expr::Group(g) => extract_len_equivalent_source(&g.expr, len_equivalents),
        Expr::MethodCall(mc) => {
            let method = mc.method.to_string();
            if matches!(
                method.as_str(),
                "len"
                    | "as_bytes"
                    | "to_ascii_lowercase"
                    | "to_ascii_uppercase"
                    | "to_string"
                    | "to_owned"
            ) && mc.args.is_empty()
            {
                let recv = normalize_expr_key(&mc.receiver);
                if !recv.is_empty() {
                    return Some(len_equivalents.get(&recv).cloned().unwrap_or(recv));
                }
            }
            if method == "replace" {
                let recv = normalize_expr_key(&mc.receiver);
                if !recv.is_empty() {
                    return Some(len_equivalents.get(&recv).cloned().unwrap_or(recv));
                }
            }
            if method == "collect"
                && mc.args.is_empty()
                && let Expr::MethodCall(inner_mc) = mc.receiver.as_ref()
                && inner_mc.method == "lines"
            {
                return Some("__non_empty_lines__".to_string());
            }
            if mc.method == "collect"
                && mc.args.is_empty()
                && let Expr::MethodCall(map_mc) = mc.receiver.as_ref()
                && map_mc.method == "map"
                && let Expr::Range(range) = unwrap_paren_group(&map_mc.receiver)
                && range
                    .start
                    .as_ref()
                    .is_some_and(|s| normalize_expr_key(s) == "0")
                && let Some(end_expr) = &range.end
            {
                if let Some(coll) = extract_len_receiver(end_expr) {
                    return Some(len_equivalents.get(&coll).cloned().unwrap_or(coll));
                }
                let end_key = normalize_expr_key(end_expr);
                if let Some(root) = len_equivalents.get(&end_key) {
                    return Some(root.clone());
                }
            }
            None
        }
        Expr::Macro(expr_macro) => {
            if expr_macro.mac.path.is_ident("vec") {
                let tokens_str = expr_macro.mac.tokens.to_string();
                if let Some((_, len_part)) = tokens_str.rsplit_once(';') {
                    let trimmed = len_part.trim().replace(' ', "");
                    if let Some(coll) = trimmed.strip_suffix(".len()") {
                        return Some(
                            len_equivalents
                                .get(coll)
                                .cloned()
                                .unwrap_or_else(|| coll.to_string()),
                        );
                    }
                    if let Some(root) = len_equivalents.get(&trimmed) {
                        return Some(root.clone());
                    }
                }
            }
            None
        }
        _ => None,
    }
}

fn unwrap_paren_group(expr: &Expr) -> &Expr {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Unwraps paren and group expressions"
    )]
    match expr {
        Expr::Paren(p) => unwrap_paren_group(&p.expr),
        Expr::Group(g) => unwrap_paren_group(&g.expr),
        other => other,
    }
}

fn extract_pattern_arg_min_len(arg: &Expr) -> usize {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Extracts byte length from string, byte-string, char, and byte literals"
    )]
    match unwrap_paren_group(arg) {
        Expr::Lit(expr_lit) => match &expr_lit.lit {
            Lit::Str(s) => s.value().len().max(1),
            Lit::ByteStr(bs) => bs.value().len().max(1),
            Lit::Char(c) => c.value().len_utf8(),
            Lit::Byte(_) => 1,
            _ => 1,
        },
        _ => 1,
    }
}

fn extract_let_pattern_bounds_guards(pat: &Pat, expr: &Expr, out: &mut Vec<SliceGuard>) {
    let Some(bound_var) = extract_some_or_ok_pat_ident(pat) else {
        return;
    };
    let inner = unwrap_try_and_error_adapters(expr);
    let Expr::MethodCall(mc) = inner else {
        return;
    };
    let method = mc.method.to_string();

    // 1. `stream.read(&mut buf)` -> `buf[..n]`
    if method == "read"
        && let Some(first_arg) = mc.args.first()
    {
        let buf_key = normalize_expr_key(first_arg);
        if !buf_key.is_empty() {
            out.push(SliceGuard {
                collection: buf_key,
                index: Some(bound_var),
                min_len: 0,
                inclusive_upper_bound: true,
            });
        }
        return;
    }

    // 2. `s.find(pat)` / `s.rfind(pat)` / `s[start..].find(pat)` / `slice.iter().position(...)`
    if matches!(method.as_str(), "find" | "rfind") {
        let (recv_key, slice_start) = extract_receiver_and_slice_start(&mc.receiver);
        if !recv_key.is_empty() {
            if slice_start.is_none() {
                out.push(SliceGuard {
                    collection: recv_key.clone(),
                    index: Some(bound_var.clone()),
                    min_len: 1,
                    inclusive_upper_bound: false,
                });
            }
            let eff_pos = match &slice_start {
                Some(sk) => format!("{sk}+{bound_var}"),
                None => bound_var.clone(),
            };
            if let Some(sk) = &slice_start {
                out.push(SliceGuard {
                    collection: recv_key.clone(),
                    index: Some(eff_pos.clone()),
                    min_len: 1,
                    inclusive_upper_bound: false,
                });
                out.push(SliceGuard {
                    collection: recv_key.clone(),
                    index: Some(format!("{bound_var}+{sk}")),
                    min_len: 1,
                    inclusive_upper_bound: false,
                });
            }
            if let Some(first_arg) = mc.args.first()
                && let Some(off) = extract_search_pat_offset(first_arg)
            {
                out.push(SliceGuard {
                    collection: recv_key.clone(),
                    index: Some(format!("{eff_pos}+{off}")),
                    min_len: 1,
                    inclusive_upper_bound: true,
                });
                if off != "1" {
                    out.push(SliceGuard {
                        collection: recv_key,
                        index: Some(format!("{eff_pos}+1")),
                        min_len: 1,
                        inclusive_upper_bound: true,
                    });
                }
            }
        }
    } else if matches!(method.as_str(), "position" | "rposition")
        && let Some(base_coll) = extract_iter_receiver(&mc.receiver)
    {
        out.push(SliceGuard {
            collection: base_coll,
            index: Some(bound_var),
            min_len: 1,
            inclusive_upper_bound: false,
        });
    } else if method == "next"
        && let Expr::MethodCall(inner_mc) = unwrap_paren_group(&mc.receiver)
        && matches!(inner_mc.method.to_string().as_str(), "chars" | "bytes")
        && inner_mc.args.is_empty()
    {
        let recv_key = normalize_expr_key(&inner_mc.receiver);
        if !recv_key.is_empty() {
            out.push(SliceGuard {
                collection: recv_key.clone(),
                index: Some("0".to_string()),
                min_len: 1,
                inclusive_upper_bound: false,
            });
            out.push(SliceGuard {
                collection: recv_key.clone(),
                index: Some("1".to_string()),
                min_len: 1,
                inclusive_upper_bound: true,
            });
            out.push(SliceGuard {
                collection: recv_key,
                index: Some(format!("{bound_var}.len_utf8()")),
                min_len: 1,
                inclusive_upper_bound: true,
            });
        }
    }
}

fn extract_search_pat_offset(arg: &Expr) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Extracts pattern length from string/char literals or variable `.len()`"
    )]
    match unwrap_paren_group(arg) {
        Expr::Lit(expr_lit) => match &expr_lit.lit {
            Lit::Str(s) => Some(s.value().len().to_string()),
            Lit::Char(c) => Some(c.value().len_utf8().to_string()),
            _ => None,
        },
        other => {
            let k = normalize_expr_key(other);
            if !k.is_empty() {
                Some(format!("{k}.len()"))
            } else {
                None
            }
        }
    }
}

fn extract_receiver_and_slice_start(receiver: &Expr) -> (String, Option<String>) {
    if let Expr::Index(expr_idx) = unwrap_paren_group(receiver)
        && let Expr::Range(range) = expr_idx.index.as_ref()
        && range.end.is_none()
        && let Some(start_expr) = &range.start
    {
        let base = normalize_expr_key(&expr_idx.expr);
        let start_key = normalize_expr_key(start_expr);
        if !base.is_empty() && !start_key.is_empty() {
            return (base, Some(start_key));
        }
    }
    (normalize_expr_key(receiver), None)
}

fn extract_search_receiver_and_offset(expr: &Expr) -> Option<(String, Option<String>)> {
    let inner = unwrap_try_and_error_adapters(expr);
    if let Expr::MethodCall(mc) = inner {
        let method = mc.method.to_string();
        if matches!(
            method.as_str(),
            "binary_search" | "binary_search_by" | "binary_search_by_key" | "find" | "rfind"
        ) {
            let recv = normalize_expr_key(&mc.receiver);
            if !recv.is_empty() {
                let off = mc.args.first().and_then(extract_search_pat_offset);
                return Some((recv, off));
            }
        } else if matches!(method.as_str(), "position" | "rposition") {
            return extract_iter_receiver(&mc.receiver).map(|r| (r, None));
        }
    }
    None
}

fn extract_turbofish_const_usize(
    turbofish: &Option<syn::AngleBracketedGenericArguments>,
) -> Option<usize> {
    let tf = turbofish.as_ref()?;
    for arg in &tf.args {
        if let syn::GenericArgument::Const(expr) = arg {
            return normalize_expr_key(expr).parse::<usize>().ok();
        }
    }
    None
}

fn extract_as_chunks_divisor_len(
    receiver: &Expr,
    fixed_array_lengths: &HashMap<String, usize>,
) -> Option<usize> {
    if let Expr::MethodCall(iter_mc) = unwrap_paren_group(receiver)
        && iter_mc.method == "iter"
        && let Expr::Field(field) = unwrap_paren_group(&iter_mc.receiver)
        && let syn::Member::Unnamed(idx) = &field.member
        && idx.index == 0
        && let Expr::MethodCall(chunks_mc) = unwrap_paren_group(&field.base)
        && chunks_mc.method == "as_chunks"
        && let Some(div_n) = extract_turbofish_const_usize(&chunks_mc.turbofish)
        && div_n >= 1
    {
        let base_key = normalize_expr_key(&chunks_mc.receiver);
        if let Some(&base_len) = fixed_array_lengths.get(&base_key) {
            return Some(base_len / div_n);
        }
    }
    None
}

fn extract_local_init_bounds_guards(
    var_name: &str,
    init_expr: &Expr,
    active_guards: &[SliceGuard],
    block_guards: &mut Vec<SliceGuard>,
) {
    let inner = unwrap_try_and_error_adapters(init_expr);
    if let Expr::MethodCall(mc) = inner {
        let method = mc.method.to_string();
        if method == "min" && mc.args.len() == 1 {
            let arg = &mc.args[0];
            let coll_opt = extract_len_or_saturating_sub_receiver(&mc.receiver)
                .or_else(|| extract_len_or_saturating_sub_receiver(arg));
            if let Some((coll, is_strict_lt)) = coll_opt {
                block_guards.push(SliceGuard {
                    collection: coll,
                    index: Some(var_name.to_string()),
                    min_len: 0,
                    inclusive_upper_bound: !is_strict_lt,
                });
                return;
            }
        }
        if method == "read"
            && let Some(first_arg) = mc.args.first()
        {
            let buf_key = normalize_expr_key(first_arg);
            if !buf_key.is_empty() {
                block_guards.push(SliceGuard {
                    collection: buf_key,
                    index: Some(var_name.to_string()),
                    min_len: 0,
                    inclusive_upper_bound: true,
                });
                return;
            }
        }
        if matches!(method.as_str(), "find" | "rfind") {
            extract_find_local_init_guards(var_name, mc, block_guards);
            return;
        }
        if method == "count"
            && mc.args.is_empty()
            && let Expr::MethodCall(tw_mc) = unwrap_paren_group(&mc.receiver)
            && tw_mc.method == "take_while"
            && let Some(base_coll) = extract_iter_receiver(&tw_mc.receiver)
        {
            block_guards.push(SliceGuard {
                collection: base_coll,
                index: Some(var_name.to_string()),
                min_len: 0,
                inclusive_upper_bound: true,
            });
            return;
        }
        if method == "unwrap_or"
            && mc.args.len() == 1
            && let Some(coll) = extract_len_receiver(&mc.args[0])
            && let Expr::MethodCall(inner_mc) = unwrap_paren_group(&mc.receiver)
            && matches!(inner_mc.method.to_string().as_str(), "find" | "rfind")
            && normalize_expr_key(&inner_mc.receiver) == coll
        {
            block_guards.push(SliceGuard {
                collection: coll,
                index: Some(var_name.to_string()),
                min_len: 0,
                inclusive_upper_bound: true,
            });
            return;
        }
    }

    if let Expr::Binary(bin) = inner
        && extract_binary_local_init_guards(var_name, bin, block_guards)
    {
        return;
    }

    let expr_key = normalize_expr_key(init_expr);
    if !expr_key.is_empty() {
        let mut derived = Vec::new();
        for g in active_guards.iter().chain(block_guards.iter()) {
            if g.collection.is_empty() {
                continue;
            }
            if g.index.as_deref() == Some(expr_key.as_str()) {
                derived.push(SliceGuard {
                    collection: g.collection.clone(),
                    index: Some(var_name.to_string()),
                    min_len: g.min_len,
                    inclusive_upper_bound: g.inclusive_upper_bound,
                });
            } else if let Some(rest) = g
                .index
                .as_deref()
                .and_then(|idx| idx.strip_prefix(&format!("{expr_key}+")))
            {
                derived.push(SliceGuard {
                    collection: g.collection.clone(),
                    index: Some(format!("{var_name}+{rest}")),
                    min_len: g.min_len,
                    inclusive_upper_bound: g.inclusive_upper_bound,
                });
            }
        }
        block_guards.extend(derived);
    }
    // `let visible = &prop_lines[..visible_count];` when `prop_lines` has `min_len >= 1`
    if let Expr::Index(expr_idx) = inner
        && let Expr::Range(range) = expr_idx.index.as_ref()
        && range.start.is_none()
    {
        let base_coll = normalize_expr_key(&expr_idx.expr);
        let base_non_empty = active_guards
            .iter()
            .chain(block_guards.iter())
            .any(|g| g.collection == base_coll && g.min_len >= 1);
        if base_non_empty {
            block_guards.push(SliceGuard {
                collection: var_name.to_string(),
                index: Some("0".to_string()),
                min_len: 1,
                inclusive_upper_bound: false,
            });
        }
    }
}

fn extract_find_local_init_guards(
    var_name: &str,
    mc: &ExprMethodCall,
    block_guards: &mut Vec<SliceGuard>,
) {
    let (recv_key, slice_start) = extract_receiver_and_slice_start(&mc.receiver);
    if recv_key.is_empty() || slice_start.is_some() {
        return;
    }
    block_guards.push(SliceGuard {
        collection: recv_key.clone(),
        index: Some(var_name.to_string()),
        min_len: 1,
        inclusive_upper_bound: false,
    });
    if let Some(first_arg) = mc.args.first()
        && let Some(off) = extract_search_pat_offset(first_arg)
    {
        block_guards.push(SliceGuard {
            collection: recv_key.clone(),
            index: Some(format!("{var_name}+{off}")),
            min_len: 1,
            inclusive_upper_bound: true,
        });
        if off != "1" {
            block_guards.push(SliceGuard {
                collection: recv_key,
                index: Some(format!("{var_name}+1")),
                min_len: 1,
                inclusive_upper_bound: true,
            });
        }
    }
}

fn extract_binary_local_init_guards(
    var_name: &str,
    bin: &ExprBinary,
    block_guards: &mut Vec<SliceGuard>,
) -> bool {
    if matches!(bin.op, BinOp::Sub(_))
        && let Some(coll) = extract_len_receiver(&bin.left)
    {
        block_guards.push(SliceGuard {
            collection: coll,
            index: Some(var_name.to_string()),
            min_len: 0,
            inclusive_upper_bound: true,
        });
        return true;
    }
    if !matches!(bin.op, BinOp::Add(_)) {
        return false;
    }
    let lhs_unwrapped = unwrap_try_and_error_adapters(&bin.left);
    let Expr::MethodCall(mc) = lhs_unwrapped else {
        return false;
    };
    if !matches!(mc.method.to_string().as_str(), "find" | "rfind") {
        return false;
    }
    let (recv_key, slice_start) = extract_receiver_and_slice_start(&mc.receiver);
    if recv_key.is_empty() {
        return false;
    }
    let rhs_key = normalize_expr_key(&bin.right);
    if let Some(sk) = slice_start {
        if rhs_key != sk {
            return false;
        }
        block_guards.push(SliceGuard {
            collection: recv_key.clone(),
            index: Some(var_name.to_string()),
            min_len: 1,
            inclusive_upper_bound: false,
        });
        if let Some(first_arg) = mc.args.first()
            && let Some(off) = extract_search_pat_offset(first_arg)
        {
            block_guards.push(SliceGuard {
                collection: recv_key,
                index: Some(format!("{var_name}+{off}")),
                min_len: 1,
                inclusive_upper_bound: true,
            });
        }
        return true;
    }
    if let Some(first_arg) = mc.args.first()
        && let Some(off) = extract_search_pat_offset(first_arg)
        && rhs_key == off
    {
        block_guards.push(SliceGuard {
            collection: recv_key,
            index: Some(var_name.to_string()),
            min_len: 1,
            inclusive_upper_bound: true,
        });
        return true;
    }
    false
}

fn extract_some_or_ok_pat_ident(pat: &Pat) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Only Some(ident) and Ok(ident) tuple-struct patterns bind single result values"
    )]
    match pat {
        Pat::TupleStruct(ts) => {
            let seg = ts.path.segments.last()?.ident.to_string();
            if matches!(seg.as_str(), "Some" | "Ok") && ts.elems.len() == 1 {
                extract_pat_ident(&ts.elems[0])
            } else {
                None
            }
        }
        _ => None,
    }
}

fn unwrap_try_and_error_adapters(expr: &Expr) -> &Expr {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Unwraps paren, group, reference, `?`, and error-adapter method calls"
    )]
    match expr {
        Expr::Paren(p) => unwrap_try_and_error_adapters(&p.expr),
        Expr::Group(g) => unwrap_try_and_error_adapters(&g.expr),
        Expr::Reference(r) => unwrap_try_and_error_adapters(&r.expr),
        Expr::Try(t) => unwrap_try_and_error_adapters(&t.expr),
        Expr::MethodCall(mc)
            if matches!(mc.method.to_string().as_str(), "map_err" | "ok" | "or_else") =>
        {
            unwrap_try_and_error_adapters(&mc.receiver)
        }
        other => other,
    }
}

fn extract_len_or_saturating_sub_receiver(expr: &Expr) -> Option<(String, bool)> {
    if let Some(coll) = extract_len_receiver(expr) {
        return Some((coll, false));
    }
    if let Expr::MethodCall(mc) = unwrap_paren_group(expr)
        && mc.method == "saturating_sub"
        && mc.args.len() == 1
        && normalize_expr_key(&mc.args[0]) == "1"
        && let Some(coll) = extract_len_receiver(&mc.receiver)
    {
        return Some((coll, true));
    }
    None
}

fn extract_while_body_reassignment_guards(
    body: &Block,
    cond_guards: &[SliceGuard],
    block_guards: &mut Vec<SliceGuard>,
) {
    for stmt in &body.stmts {
        extract_single_while_stmt_guard(stmt, cond_guards, block_guards);
    }
}

fn extract_single_while_stmt_guard(
    stmt: &Stmt,
    cond_guards: &[SliceGuard],
    block_guards: &mut Vec<SliceGuard>,
) {
    if let Stmt::Local(local) = stmt
        && let Some((name, _)) = extract_local_ident_and_type(&local.pat)
        && let Some(init) = &local.init
    {
        let init_key = normalize_expr_key(&init.expr);
        if !init_key.is_empty() {
            let derived = derive_aliased_guards(&name, &init_key, cond_guards, block_guards);
            block_guards.extend(derived);
        }
    } else if let Stmt::Expr(Expr::Assign(assign), _) = stmt {
        let lhs_key = normalize_expr_key(&assign.left);
        let rhs_key = normalize_expr_key(&assign.right);
        if !lhs_key.is_empty() && !rhs_key.is_empty() {
            let derived: Vec<SliceGuard> = cond_guards
                .iter()
                .chain(block_guards.iter())
                .filter(|g| {
                    !g.collection.is_empty() && g.index.as_deref() == Some(rhs_key.as_str())
                })
                .map(|g| SliceGuard {
                    collection: g.collection.clone(),
                    index: Some(lhs_key.clone()),
                    min_len: g.min_len,
                    inclusive_upper_bound: g.inclusive_upper_bound,
                })
                .collect();
            block_guards.extend(derived);
        }
    } else if let Stmt::Expr(Expr::Binary(bin), _) = stmt
        && matches!(bin.op, BinOp::SubAssign(_))
    {
        let lhs_key = normalize_expr_key(&bin.left);
        let rhs_key = normalize_expr_key(&bin.right);
        if !lhs_key.is_empty() && rhs_key.parse::<usize>().is_ok_and(|k| k >= 1) {
            for g in block_guards.iter_mut() {
                if !g.collection.is_empty() && g.index.as_deref() == Some(lhs_key.as_str()) {
                    g.inclusive_upper_bound = false;
                }
            }
        }
    }
}

fn derive_aliased_guards(
    name: &str,
    init_key: &str,
    cond_guards: &[SliceGuard],
    block_guards: &[SliceGuard],
) -> Vec<SliceGuard> {
    let mut derived = Vec::new();
    for g in cond_guards.iter().chain(block_guards.iter()) {
        if g.collection.is_empty() {
            continue;
        }
        if g.index.as_deref() == Some(init_key) {
            derived.push(SliceGuard {
                collection: g.collection.clone(),
                index: Some(name.to_string()),
                min_len: g.min_len,
                inclusive_upper_bound: g.inclusive_upper_bound,
            });
        } else if let Some(rest) = g
            .index
            .as_deref()
            .and_then(|idx| idx.strip_prefix(&format!("{init_key}+")))
        {
            derived.push(SliceGuard {
                collection: g.collection.clone(),
                index: Some(format!("{name}+{rest}")),
                min_len: g.min_len,
                inclusive_upper_bound: g.inclusive_upper_bound,
            });
        }
    }
    derived
}

fn extract_post_stmt_bounds_guards(stmt: &Stmt, block_guards: &mut Vec<SliceGuard>) {
    match stmt {
        Stmt::Expr(Expr::If(expr_if), _) => {
            if block_always_diverges(&expr_if.then_branch) {
                extract_cond_bounds_guards(&expr_if.cond, true, block_guards);
            }
        }
        Stmt::Expr(Expr::Assign(assign), _) => {
            let lhs_key = normalize_expr_key(&assign.left);
            let rhs_key = normalize_expr_key(&assign.right);
            if !lhs_key.is_empty() && !rhs_key.is_empty() {
                let mut derived = Vec::new();
                for g in block_guards.iter() {
                    if g.collection.is_empty() {
                        continue;
                    }
                    if g.index.as_deref() == Some(rhs_key.as_str()) {
                        derived.push(SliceGuard {
                            collection: g.collection.clone(),
                            index: Some(lhs_key.clone()),
                            min_len: g.min_len,
                            inclusive_upper_bound: g.inclusive_upper_bound,
                        });
                    }
                }
                block_guards.extend(derived);
            }
        }
        Stmt::Expr(Expr::Binary(bin), _) if matches!(bin.op, BinOp::SubAssign(_)) => {
            let lhs_key = normalize_expr_key(&bin.left);
            let rhs_key = normalize_expr_key(&bin.right);
            if !lhs_key.is_empty() && rhs_key.parse::<usize>().is_ok_and(|k| k >= 1) {
                for g in block_guards.iter_mut() {
                    if !g.collection.is_empty() && g.index.as_deref() == Some(lhs_key.as_str()) {
                        g.inclusive_upper_bound = false;
                    }
                }
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
    matches!(expr, Expr::Return(_) | Expr::Break(_) | Expr::Continue(_))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_cast_findings(src: &str) -> Vec<RsCandidateFinding> {
        let ast = syn::parse_file(src).expect("valid Rust syntax");
        let lines: Vec<&str> = src.lines().collect();
        let line_starts = dotore_core::compute_line_starts(src);
        let mut findings = Vec::new();
        extract_safety_findings(&ast, &lines, &line_starts, &mut findings);
        findings
            .into_iter()
            .filter(|f| f.rule == RuleId::RsNoLossyNumericAsCast)
            .collect()
    }

    fn check_slice_index_findings(src: &str) -> Vec<RsCandidateFinding> {
        let ast = syn::parse_file(src).expect("valid Rust syntax");
        let lines: Vec<&str> = src.lines().collect();
        let line_starts = dotore_core::compute_line_starts(src);
        let mut findings = Vec::new();
        extract_safety_findings(&ast, &lines, &line_starts, &mut findings);
        findings
            .into_iter()
            .filter(|f| f.rule == RuleId::RsNoUnguardedSliceIndex)
            .collect()
    }

    #[test]
    fn while_loop_and_short_circuit_boolean_guards_protect_slice_indexing() {
        let src = r#"
pub fn scan_bytes(bytes: &[u8], p: &[u8], t: &[u8]) -> usize {
    let mut pos = 0usize;
    while pos < bytes.len() && bytes[pos] != b'\n' {
        if bytes[pos] == b'\\' {
            pos += 1;
        }
        pos += 1;
    }
    let pi = 0usize;
    let ti = 0usize;
    if pi < p.len() && ti < t.len() && (p[pi] == b'?' || p[pi] == t[ti]) {
        pos += 1;
    }
    if pos >= bytes.len() || bytes[pos] == b'(' {
        pos += 1;
    }
    pos
}
"#;
        let findings = check_slice_index_findings(src);
        assert!(
            findings.is_empty(),
            "Expected 0 slice index findings for while/short-circuit guards, got: {findings:#?}"
        );
    }

    #[test]
    fn exact_and_min_length_comparisons_and_arithmetic_offsets_guard_slice_indexing() {
        let src = r#"
pub fn length_and_offset_guards(
    tokens: &[&str],
    parts: &[&str],
    scc: &[usize],
    bytes: &[u8],
    components: &[&str],
    idx: usize,
) -> usize {
    let mut acc = 0usize;
    if tokens.len() >= 3 {
        acc += tokens[0].len() + tokens[1].len() + tokens[2].len();
    }
    if parts.len() == 3 {
        acc += parts[0].len() + parts[1].len() + parts[2].len();
    }
    if scc.len() > 1 {
        acc += scc[0] + scc[1];
    }
    if idx + 1 < bytes.len() {
        acc += usize::from(bytes[idx]) + usize::from(bytes[idx + 1]);
    }
    if idx > 0 && idx < bytes.len() {
        acc += usize::from(bytes[idx - 1]);
    }
    if components.len() >= 3 {
        acc += components[..components.len() - 2].len();
        acc += components[components.len() - 1].len();
    }
    if scc.len() != 2 {
        return acc;
    }
    acc + scc[0] + scc[1]
}
"#;
        let findings = check_slice_index_findings(src);
        assert!(
            findings.is_empty(),
            "Expected 0 slice index findings for length and arithmetic offset guards, got: {findings:#?}"
        );
    }

    #[test]
    fn bounded_for_loops_const_arrays_windows_modulo_read_exact_and_parallel_vecs_are_guarded() {
        let src = r#"
const SHA256_K: [u32; 64] = [0; 64];
const SPINNER_FRAMES: &[char] = &['a', 'b', 'c', 'd'];

pub struct Reader;
impl Reader {
    fn read_exact_bytes(&mut self, n: usize) -> Result<Vec<u8>, String> {
        Ok(vec![0; n])
    }
}

pub fn idioms(
    items: &[u32],
    render_calls: &[(u32, u32)],
    tick: usize,
    reader: &mut Reader,
) -> Result<u32, String> {
    let mut w = [0u32; 64];
    for i in 16..64 {
        w[i] = w[i - 16].wrapping_add(w[i - 15]).wrapping_add(w[i - 7]).wrapping_add(w[i - 2]);
    }
    let mut acc = 0u32;
    for i in 0..64 {
        acc = acc.wrapping_add(SHA256_K[i]).wrapping_add(w[i]);
    }
    for i in 1..render_calls.len() {
        if render_calls[i].0 == render_calls[i - 1].0 {
            acc += render_calls[i].1;
        }
    }
    for window in items.windows(2) {
        acc += window[0] + window[1];
    }
    let mask = [1u8, 2, 3, 4];
    for (idx, _) in items.iter().enumerate() {
        acc += items[idx] + u32::from(mask[idx % 4]);
    }
    let _ch = SPINNER_FRAMES[tick % SPINNER_FRAMES.len()];
    let hdr = reader.read_exact_bytes(2)?;
    let ext = reader.read_exact_bytes(8)?;
    acc += u32::from(hdr[0]) + u32::from(hdr[1]) + u32::from(ext[7]);

    let n = items.len();
    let mut visited = vec![false; n];
    let mut buckets: Vec<Vec<u32>> = (0..items.len()).map(|_| Vec::new()).collect();
    for idx in 0..n {
        if !visited[idx] {
            visited[idx] = true;
            buckets[idx].push(items[idx]);
        }
    }
    Ok(acc)
}
"#;
        let findings = check_slice_index_findings(src);
        assert!(
            findings.is_empty(),
            "Expected 0 slice index findings for bounded loops/arrays/windows/modulo/parallel vecs, got: {findings:#?}"
        );
    }

    #[test]
    fn search_clamp_read_as_bytes_and_json_key_indexing_are_guarded() {
        let src = r#"
pub fn search_and_clamp_idioms(
    raw_url: &str,
    source: &str,
    byte_pos: usize,
    prop_lines: &[(u32, &str)],
    line: &str,
    stream: &mut dyn std::io::Read,
    val: &serde_json::Value,
) -> Result<usize, String> {
    let mut acc = 0usize;
    let (_, after_scheme) = raw_url.split_once("://").unwrap_or(("http", raw_url));
    let (authority, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, "/"),
    };
    acc += authority.len() + path.len();

    if let Some(open_paren) = line.find('(')
        && line.ends_with(')')
    {
        let callee = line[..open_paren].trim();
        let args = &line[open_paren + 1..line.len() - 1];
        acc += callee.len() + args.len();
    }

    let prefix = &source[..byte_pos.min(source.len())];
    let line_start = prefix.rfind('\n').map_or(0, |idx| idx + 1);
    acc += source[line_start..byte_pos.min(source.len())].len();

    if !prop_lines.is_empty() {
        let visible_count = prop_lines.len().min(10);
        let visible = &prop_lines[..visible_count];
        acc += visible[0].1.len();
    }

    if line.len() >= 7 && &line.as_bytes()[4..7] == b" | " {
        acc += 7;
    }
    if let Some(fetch_pos) = line.find("fetch(")
        && fetch_pos > 0
        && line.as_bytes()[fetch_pos - 1].is_ascii_alphanumeric()
    {
        acc += 1;
    }

    let mut temp = [0u8; 512];
    let n = stream.read(&mut temp).map_err(|e| e.to_string())?;
    acc += temp[..n].len();

    let _session = &val["result"]["value"];
    Ok(acc)
}
"#;
        let findings = check_slice_index_findings(src);
        assert!(
            findings.is_empty(),
            "Expected 0 slice index findings for search/clamp/read/as_bytes/json key idioms, got: {findings:#?}"
        );
    }

    #[test]
    fn substring_search_offsets_match_indices_binary_search_and_cursor_decrement_are_guarded() {
        let src = r#"
pub fn substring_and_cursor_idioms(
    source: &str,
    pattern: &str,
    glsl: &str,
    needle: &str,
    haystack: &str,
    ident: &str,
    lines: &[&str],
    start_idx: usize,
) -> Option<usize> {
    let mut acc = 0usize;
    let mut search_from = 0usize;
    while let Some(rel) = source[search_from..].find(pattern) {
        let hit = search_from + rel;
        let after_name = &source[hit + pattern.len()..];
        acc += after_name.len();
        search_from = hit + pattern.len();
    }

    let start = glsl.find(needle)? + needle.len();
    let end = glsl[start..].find(')')? + start;
    acc += glsl[start..end].len();

    for (idx, _) in haystack.match_indices(ident) {
        let before_ok = idx == 0 || !haystack.as_bytes()[idx - 1].is_ascii_alphanumeric();
        let after_idx = idx + ident.len();
        let after_ok = after_idx == haystack.len() || !haystack.as_bytes()[after_idx].is_ascii_alphanumeric();
        if before_ok && after_ok {
            acc += 1;
        }
    }

    let found = lines.binary_search(&needle).ok().map(|idx| lines[idx].len()).unwrap_or(0);
    acc += found;

    let mut cursor = start_idx.min(lines.len().saturating_sub(1));
    while cursor > 0 {
        cursor -= 1;
        acc += lines[cursor].len();
    }
    Some(acc)
}
"#;
        let findings = check_slice_index_findings(src);
        assert!(
            findings.is_empty(),
            "Expected 0 slice index findings for substring search, match_indices, binary_search, and cursor decrement, got: {findings:#?}"
        );
    }

    #[test]
    fn char_indices_take_while_and_subslice_ranges_are_guarded() {
        let src = r#"
pub fn char_indices_and_subslice_idioms(
    spec: &str,
    stmt_line: &str,
    hint: &str,
    lines: &[&str],
) -> Option<usize> {
    let mut acc = 0usize;
    for (idx, ch) in spec.char_indices() {
        if ch == '=' {
            acc += spec[..idx].len() + spec[idx..].len();
        }
    }
    let indent_len = stmt_line.len() - stmt_line.trim_start().len();
    acc += stmt_line[..indent_len].len();

    if let Some(first) = hint.chars().next() {
        acc += hint[first.len_utf8()..].len();
    }

    for (i, _) in lines.iter().enumerate() {
        for &body_line in &lines[i + 1..] {
            acc += body_line.len();
        }
    }

    let len = spec.bytes().take_while(|b| b.is_ascii_alphanumeric()).count();
    acc += spec[..len].len();

    let open = spec.find('(')?;
    let after = &spec[open + 1..];
    acc += after.len();

    Some(acc)
}
"#;
        let findings = check_slice_index_findings(src);
        assert!(
            findings.is_empty(),
            "Expected 0 slice index findings for char_indices/take_while/subslice, got: {findings:#?}"
        );
    }

    #[test]
    fn lowercase_as_bytes_equivalence_and_as_chunks_are_guarded() {
        let src = r#"
pub fn lowercase_and_chunks_idioms(
    line: &str,
    input: &str,
    padded: &[u8],
    h: [u32; 8],
) -> usize {
    let mut acc = 0usize;
    let l = line.to_ascii_lowercase();
    if let Some(pos) = l.find("create table") {
        acc += line[pos + "create table".len()..].len();
    }

    let bytes = input.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some(ch) = input[i..].chars().next() {
            acc += ch.len_utf8();
        }
        i += 1;
    }

    let mut w = [0u32; 64];
    for chunk in padded.as_chunks::<64>().0 {
        for (idx, word) in chunk.as_chunks::<4>().0.iter().enumerate() {
            w[idx] = u32::from_be_bytes(*word);
        }
    }
    let mut out = [0u8; 32];
    for (idx, word) in h.iter().enumerate() {
        out[idx * 4..idx * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    acc += usize::from(out[0]) + (w[0] as usize);
    acc
}
"#;
        let findings = check_slice_index_findings(src);
        assert!(
            findings.is_empty(),
            "Expected 0 slice index findings for lowercase/as_bytes equivalence and as_chunks, got: {findings:#?}"
        );
    }

    #[test]
    fn unguarded_slice_and_string_indexing_sites_including_s_and_files_are_flagged() {
        let src = r#"
pub fn unguarded_sites(
    items: &[u64],
    groups: &[u32],
    hex: &str,
    s: &str,
    files: &[&str],
    idx: usize,
) -> u64 {
    let a = items[idx];
    let b = u64::from(groups[0]);
    let c = hex[0..2].len() as u64;
    let d = (&s[0..5]).len() as u64;
    let e = files[idx].len() as u64;
    a + b + c + d + e
}
"#;
        let findings = check_slice_index_findings(src);
        assert_eq!(
            findings.len(),
            5,
            "Expected all 5 unguarded slice/string index sites (including `&s[0..5]` and `files[idx]`) to be flagged, got: {findings:#?}"
        );
    }

    #[test]
    fn widening_span_fields_masked_casts_from_bytes_and_enum_discriminants_are_lossless() {
        let src = r#"
#[repr(u16)]
#[derive(Clone, Copy)]
pub enum Kind {
    A = 0,
    B = 1,
}

impl Kind {
    pub const fn index(self) -> usize {
        self as usize
    }
}

pub struct Span {
    pub start: u32,
    pub end: u32,
    pub line: u32,
    pub column: u32,
    pub index: u32,
    pub health_score: u8,
}

pub fn lossless_casts(span: Span, hdr: &[u8], ext: [u8; 2], buf: u32, bits: u32, text: &str) -> usize {
    let a = span.start as usize;
    let b = span.end.saturating_sub(span.start) as usize;
    let c = (span.line - 1) as usize;
    let d = span.column as usize + span.index as usize + span.health_score as usize;
    let e = ((buf >> bits) & 0xff) as u8;
    let f = (hdr.get(1).copied().unwrap_or(0) & 0x7f) as usize;
    let g = u16::from_be_bytes(ext) as usize;
    let h = u8::from_le_bytes([ext[0]]) as u32;
    let mut char_sum = 0u32;
    for ch in text.chars() {
        char_sum += ch as u32;
    }
    a + b + c + d + usize::from(e) + f + g + (h as usize) + (char_sum as usize)
}
"#;
        let findings = check_cast_findings(src);
        assert!(
            findings.is_empty(),
            "Expected 0 lossy cast findings on lossless casts, got: {findings:#?}"
        );
    }

    #[test]
    fn narrowing_sign_changing_float_to_int_and_overwide_mask_casts_are_flagged() {
        let src = r#"
pub struct NumLit {
    pub value: f64,
}

pub fn lossy_casts(
    big: u64,
    idx: usize,
    signed: i32,
    unsigned: u32,
    flt: f64,
    num: NumLit,
) -> usize {
    let a = big as u32;
    let b = idx as u32;
    let c = (big + 1) as u32;
    let d = signed as u32;
    let e = unsigned as i32;
    let f = flt as u32;
    let g = flt as usize;
    let h = num.value as usize;
    let i = signed as usize;
    let j = big as usize;
    let k = (big & 0x1ff) as u8;
    (a as usize) + (b as usize) + (c as usize) + (d as usize) + (e as usize) + (f as usize) + g + h + i + j + usize::from(k)
}
"#;
        let findings = check_cast_findings(src);
        assert_eq!(
            findings.len(),
            12,
            "Expected all 12 lossy casts (including `e as usize` from `i32`) to be flagged, got {}: {findings:#?}",
            findings.len()
        );
    }
}
