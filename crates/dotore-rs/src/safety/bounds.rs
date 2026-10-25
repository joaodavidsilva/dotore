//! Slice bounds-guard verification, `for`-loop bounds collection, and fixed-size array /
//! length-equivalence helpers for `safety.rs`.

use std::collections::HashMap;

use syn::{Block, Expr, ExprForLoop, ExprIf, ExprIndex, ExprMethodCall, Lit, Pat, Stmt, Type};

use crate::matchers::{extract_pat_ident, normalize_expr_key};

use super::{SafetyVisitor, casts::NumericType, guards::{extract_len_receiver, unwrap_try_and_error_adapters}};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SliceGuard {
    pub collection: String,
    pub index: Option<String>,
    pub min_len: usize,
    pub inclusive_upper_bound: bool,
}

impl SafetyVisitor<'_> {
    pub(super) fn collections_share_len(&self, a: &str, b: &str) -> bool {
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

    pub(super) fn is_slice_index_guarded(&self, expr_index: &ExprIndex) -> bool {
        if let Expr::Lit(expr_lit) = unwrap_paren_group(&expr_index.index)
            && matches!(expr_lit.lit, Lit::Str(_))
        {
            return true;
        }
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

        let known_len = self.fixed_array_lengths.get(&coll_key).copied();
        if let Some(len) = known_len
            && let Some(NumericType::UnsuffixedInt(idx_val)) =
                self.infer_expr_numeric_type(&expr_index.index)
            && idx_val >= 0
            && usize::try_from(idx_val).is_ok_and(|u| u < len)
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
        self.is_modulo_index_guarded(&idx_key, &coll_key, known_len, &all_guards)
            || self.is_sub_offset_index_guarded(&idx_key, &coll_key, known_len, &all_guards)
            || self.is_direct_guard_matching_index(&idx_key, &coll_key, known_len, &all_guards)
    }

    fn is_modulo_index_guarded(
        &self,
        idx_key: &str,
        coll_key: &str,
        known_len: Option<usize>,
        all_guards: &[&SliceGuard],
    ) -> bool {
        let Some((_, rhs_mod)) = idx_key.rsplit_once('%') else {
            return false;
        };
        if let Ok(mod_n) = rhs_mod.parse::<usize>()
            && mod_n >= 1
            && known_len.is_some_and(|len| mod_n <= len)
        {
            return true;
        }
        rhs_mod == format!("{coll_key}.len()")
            && (known_len.is_some_and(|len| len >= 1)
                || all_guards
                    .iter()
                    .any(|g| self.collections_share_len(&g.collection, coll_key) && g.min_len >= 1))
    }

    fn is_sub_offset_index_guarded(
        &self,
        idx_key: &str,
        coll_key: &str,
        known_len: Option<usize>,
        all_guards: &[&SliceGuard],
    ) -> bool {
        let Some((base_var, sub_lit)) = idx_key.rsplit_once('-') else {
            return false;
        };
        let Ok(k) = sub_lit.parse::<usize>() else {
            return false;
        };
        if base_var == format!("{coll_key}.len()") {
            return known_len.is_some_and(|len| len >= k)
                || all_guards.iter().any(|g| {
                    self.collections_share_len(&g.collection, coll_key)
                        && (g.min_len >= k
                            || (k == 1 && !g.inclusive_upper_bound && g.index.is_some()))
                });
        }
        let base_bounded = all_guards.iter().any(|g| {
            !g.inclusive_upper_bound
                && g.index.as_deref() == Some(base_var)
                && (self.collections_share_len(&g.collection, coll_key)
                    || (g.collection.is_empty() && known_len.is_some_and(|len| g.min_len <= len)))
        });
        let base_ge_k = all_guards.iter().any(|g| {
            g.collection.is_empty() && g.index.as_deref() == Some(base_var) && g.min_len >= k
        });
        base_bounded && base_ge_k
    }

    fn is_direct_guard_matching_index(
        &self,
        idx_key: &str,
        coll_key: &str,
        known_len: Option<usize>,
        all_guards: &[&SliceGuard],
    ) -> bool {
        let parsed_idx = idx_key.parse::<usize>().ok();
        for g in all_guards {
            if g.collection.is_empty() {
                if !g.inclusive_upper_bound
                    && g.index.as_deref() == Some(idx_key)
                    && known_len.is_some_and(|len| g.min_len > 0 && g.min_len <= len)
                {
                    return true;
                }
                continue;
            }
            if !self.collections_share_len(&g.collection, coll_key) {
                continue;
            }
            if !g.inclusive_upper_bound && g.index.as_deref() == Some(idx_key) {
                return true;
            }
            if let Some(n) = parsed_idx
                && (n < g.min_len || (n == 0 && !g.inclusive_upper_bound && g.index.is_some()))
            {
                return true;
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
            reason = "Only `.min(coll.len())` method calls form clamping bounds (#50)"
        )]
        match unwrap_paren_group(expr) {
            Expr::MethodCall(mc) if mc.method == "min" && mc.args.len() == 1 => {
                let Some(arg) = mc.args.first() else {
                    return false;
                };
                extract_len_receiver(&mc.receiver)
                    .is_some_and(|c| self.collections_share_len(&c, coll_key))
                    || extract_len_receiver(arg)
                        .is_some_and(|c| self.collections_share_len(&c, coll_key))
            }
            _ => false,
        }
    }

    pub(super) fn collect_for_loop_guards(
        &mut self,
        i: &ExprForLoop,
        added_window_var: &mut Option<String>,
    ) {
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
        if matches!(method.as_str(), "enumerate" | "char_indices") {
            self.collect_enumerate_or_char_indices_guards(&method, mc, pat);
        } else if method == "match_indices" {
            self.collect_match_indices_guards(mc, pat);
        } else if matches!(method.as_str(), "windows" | "chunks_exact")
            && let Some(first_arg) = mc.args.first()
            && let Ok(win_len) = normalize_expr_key(first_arg).parse::<usize>()
            && let Some(win_var) = extract_pat_ident(pat)
        {
            self.fixed_array_lengths.insert(win_var.clone(), win_len);
            *added_window_var = Some(win_var);
        }
    }

    fn collect_enumerate_or_char_indices_guards(
        &mut self,
        method: &str,
        mc: &ExprMethodCall,
        pat: &Pat,
    ) {
        let Pat::Tuple(pat_tuple) = pat else {
            return;
        };
        let Some(first_pat) = pat_tuple.elems.first() else {
            return;
        };
        let Some(idx_var) = extract_pat_ident(first_pat) else {
            return;
        };
        let Some(base_coll) = extract_iter_receiver(&mc.receiver) else {
            return;
        };
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
    }

    fn collect_match_indices_guards(&mut self, mc: &ExprMethodCall, pat: &Pat) {
        let Pat::Tuple(pat_tuple) = pat else {
            return;
        };
        let Some(first_pat) = pat_tuple.elems.first() else {
            return;
        };
        let Some(idx_var) = extract_pat_ident(first_pat) else {
            return;
        };
        let recv_key = normalize_expr_key(&mc.receiver);
        if recv_key.is_empty() {
            return;
        }
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
}

pub(super) fn extract_fixed_array_type_len(ty: &Type) -> Option<usize> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Only fixed-size array types and wrappers carry compile-time array length (#50)"
    )]
    match ty {
        Type::Array(arr) => normalize_expr_key(&arr.len).parse::<usize>().ok(),
        Type::Reference(tr) => extract_fixed_array_type_len(&tr.elem),
        Type::Paren(p) => extract_fixed_array_type_len(&p.elem),
        Type::Group(g) => extract_fixed_array_type_len(&g.elem),
        _ => None,
    }
}

pub(super) fn extract_fixed_array_expr_len(expr: &Expr) -> Option<usize> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Only array/repeat literals and fixed-size constructors yield known static lengths (#50)"
    )]
    match unwrap_paren_group(expr) {
        Expr::Reference(r) => extract_fixed_array_expr_len(&r.expr),
        Expr::Try(t) => extract_fixed_array_expr_len(&t.expr),
        Expr::Array(arr) => Some(arr.elems.len()),
        Expr::Repeat(rep) => normalize_expr_key(&rep.len).parse::<usize>().ok(),
        Expr::MethodCall(mc) if mc.method == "read_exact_bytes" => mc
            .args
            .first()
            .and_then(|arg| normalize_expr_key(arg).parse::<usize>().ok()),
        Expr::If(expr_if) => extract_if_fixed_array_len(expr_if),
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

fn extract_if_fixed_array_len(expr_if: &ExprIf) -> Option<usize> {
    let then_len = extract_tail_stmt_array_len(&expr_if.then_branch)?;
    if let Some((_, else_expr)) = &expr_if.else_branch {
        let else_len = if let Expr::Block(b) = else_expr.as_ref() {
            extract_tail_stmt_array_len(&b.block)?
        } else {
            extract_fixed_array_expr_len(else_expr)?
        };
        Some(then_len.min(else_len))
    } else {
        Some(then_len)
    }
}

fn extract_tail_stmt_array_len(block: &Block) -> Option<usize> {
    match block.stmts.last()? {
        Stmt::Expr(e, _) => extract_fixed_array_expr_len(e),
        Stmt::Local(_) | Stmt::Item(_) | Stmt::Macro(_) => None,
    }
}

pub(super) fn extract_iter_receiver(expr: &Expr) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Iterator receiver unwrapping inspects method calls and falls back to direct expression key (#50)"
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

pub(super) fn extract_len_equivalent_source(
    expr: &Expr,
    len_equivalents: &HashMap<String, String>,
) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Length equivalence inspects method calls and vec! macros (#50)"
    )]
    match unwrap_paren_group(expr) {
        Expr::MethodCall(mc) => extract_method_len_equivalent(mc, len_equivalents),
        Expr::Macro(expr_macro) => extract_vec_macro_len_equivalent(expr_macro, len_equivalents),
        _ => None,
    }
}

fn extract_method_len_equivalent(
    mc: &ExprMethodCall,
    len_equivalents: &HashMap<String, String>,
) -> Option<String> {
    let method = mc.method.to_string();
    let is_len_preserving_zero_arg = matches!(
        method.as_str(),
        "len"
            | "as_bytes"
            | "to_ascii_lowercase"
            | "to_ascii_uppercase"
            | "to_string"
            | "to_owned"
    ) && mc.args.is_empty();
    if is_len_preserving_zero_arg || method == "replace" {
        let recv = normalize_expr_key(&mc.receiver);
        if !recv.is_empty() {
            return Some(len_equivalents.get(&recv).cloned().unwrap_or(recv));
        }
        return None;
    }
    if method == "collect" && mc.args.is_empty() {
        return extract_collect_len_equivalent(&mc.receiver, len_equivalents);
    }
    None
}

fn extract_collect_len_equivalent(
    receiver: &Expr,
    len_equivalents: &HashMap<String, String>,
) -> Option<String> {
    let Expr::MethodCall(inner_mc) = receiver else {
        return None;
    };
    if inner_mc.method == "lines" {
        return Some("__non_empty_lines__".to_string());
    }
    if inner_mc.method == "map"
        && let Expr::Range(range) = unwrap_paren_group(&inner_mc.receiver)
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
        return len_equivalents.get(&end_key).cloned();
    }
    None
}

fn extract_vec_macro_len_equivalent(
    expr_macro: &syn::ExprMacro,
    len_equivalents: &HashMap<String, String>,
) -> Option<String> {
    if !expr_macro.mac.path.is_ident("vec") {
        return None;
    }
    let tokens_str = expr_macro.mac.tokens.to_string();
    let (_, len_part) = tokens_str.rsplit_once(';')?;
    let trimmed = len_part.trim().replace(' ', "");
    if let Some(coll) = trimmed.strip_suffix(".len()") {
        return Some(
            len_equivalents
                .get(coll)
                .cloned()
                .unwrap_or_else(|| coll.to_string()),
        );
    }
    len_equivalents.get(&trimmed).cloned()
}

pub(super) fn unwrap_paren_group(expr: &Expr) -> &Expr {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Unwraps paren and group expressions (#50)"
    )]
    match expr {
        Expr::Paren(p) => unwrap_paren_group(&p.expr),
        Expr::Group(g) => unwrap_paren_group(&g.expr),
        other => other,
    }
}

pub(super) fn extract_search_pat_offset(arg: &Expr) -> Option<String> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Extracts pattern length from string/char literals or variable `.len()` (#50)"
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

pub(super) fn extract_receiver_and_slice_start(receiver: &Expr) -> (String, Option<String>) {
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

pub(super) fn extract_search_receiver_and_offset(expr: &Expr) -> Option<(String, Option<String>)> {
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
