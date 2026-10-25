//! Condition, `let`-pattern, local-initializer, `while`-body, and post-statement
//! slice bounds-guard extraction for `safety.rs`.

use syn::{BinOp, Block, Expr, ExprBinary, ExprMethodCall, Lit, Pat, Stmt, UnOp};

use crate::matchers::{extract_pat_ident, normalize_expr_key};

use super::{
    bounds::{
        SliceGuard, extract_iter_receiver, extract_receiver_and_slice_start,
        extract_search_pat_offset, unwrap_paren_group,
    },
    casts::extract_local_ident_and_type,
};

pub(super) fn extract_cond_bounds_guards(cond: &Expr, negated: bool, out: &mut Vec<SliceGuard>) {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Condition guard extraction inspects logical connectives, unary negation, method calls, and comparisons (#50)"
    )]
    match unwrap_paren_group(cond) {
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
        Expr::MethodCall(mc) => extract_method_call_cond_guard(mc, negated, out),
        _ => {}
    }
}

fn extract_method_call_cond_guard(
    mc: &ExprMethodCall,
    negated: bool,
    out: &mut Vec<SliceGuard>,
) {
    let method = mc.method.to_string();
    let recv = normalize_expr_key(&mc.receiver);
    if recv.is_empty() {
        return;
    }
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
    if let Some(coll) = extract_len_receiver(right) {
        let idx_key = normalize_expr_key(left);
        if !idx_key.is_empty() {
            record_rhs_len_comparison_guard(coll, idx_key, cmp, out);
        }
        return;
    }
    if let Some(coll) = extract_len_receiver(left) {
        let idx_key = normalize_expr_key(right);
        if !idx_key.is_empty() {
            record_lhs_len_comparison_guard(coll, idx_key, cmp, out);
        }
        return;
    }
    record_index_lower_bound_guard(
        normalize_expr_key(left),
        normalize_expr_key(right),
        cmp,
        out,
    );
}

fn push_plus_offset_base_guard(coll: String, idx_key: &str, out: &mut Vec<SliceGuard>) {
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

fn record_rhs_len_comparison_guard(
    coll: String,
    idx_key: String,
    cmp: EffectiveCmp,
    out: &mut Vec<SliceGuard>,
) {
    let lit_val = idx_key.parse::<usize>().ok();
    match cmp {
        EffectiveCmp::Lt => {
            out.push(SliceGuard {
                collection: coll.clone(),
                index: Some(idx_key.clone()),
                min_len: lit_val.map_or(1, |n| n + 1),
                inclusive_upper_bound: false,
            });
            push_plus_offset_base_guard(coll, &idx_key, out);
        }
        EffectiveCmp::Le => {
            out.push(SliceGuard {
                collection: coll.clone(),
                index: Some(idx_key.clone()),
                min_len: lit_val.unwrap_or(0),
                inclusive_upper_bound: true,
            });
            push_plus_offset_base_guard(coll, &idx_key, out);
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

fn record_lhs_len_comparison_guard(
    coll: String,
    idx_key: String,
    cmp: EffectiveCmp,
    out: &mut Vec<SliceGuard>,
) {
    let lit_val = idx_key.parse::<usize>().ok();
    match cmp {
        EffectiveCmp::Gt => {
            out.push(SliceGuard {
                collection: coll.clone(),
                index: Some(idx_key.clone()),
                min_len: lit_val.map_or(1, |n| n + 1),
                inclusive_upper_bound: false,
            });
            push_plus_offset_base_guard(coll, &idx_key, out);
        }
        EffectiveCmp::Ge => {
            out.push(SliceGuard {
                collection: coll,
                index: Some(idx_key),
                min_len: lit_val.unwrap_or(0),
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

fn record_index_lower_bound_guard(
    left_key: String,
    right_key: String,
    cmp: EffectiveCmp,
    out: &mut Vec<SliceGuard>,
) {
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
    reason = "syn::BinOp is non-exhaustive; only comparison operators form bounds guards (#50)"
)]
const fn resolve_effective_cmp(op: &BinOp, negated: bool) -> Option<EffectiveCmp> {
    let direct = match op {
        BinOp::Lt(_) => Some(EffectiveCmp::Lt),
        BinOp::Le(_) => Some(EffectiveCmp::Le),
        BinOp::Gt(_) => Some(EffectiveCmp::Gt),
        BinOp::Ge(_) => Some(EffectiveCmp::Ge),
        BinOp::Ne(_) => Some(EffectiveCmp::Ne),
        BinOp::Eq(_) => Some(EffectiveCmp::Eq),
        _ => None,
    };
    match (direct, negated) {
        (Some(c), true) => Some(c.negate()),
        (other, false) => other,
        (None, true) => None,
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

impl EffectiveCmp {
    const fn negate(self) -> Self {
        match self {
            Self::Lt => Self::Ge,
            Self::Le => Self::Gt,
            Self::Gt => Self::Le,
            Self::Ge => Self::Lt,
            Self::Ne => Self::Eq,
            Self::Eq => Self::Ne,
        }
    }
}

pub(super) fn extract_len_receiver(expr: &Expr) -> Option<String> {
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

fn extract_pattern_arg_min_len(arg: &Expr) -> usize {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Extracts byte length from string, byte-string, char, and byte literals (#50)"
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

pub(super) fn extract_let_pattern_bounds_guards(
    pat: &Pat,
    expr: &Expr,
    out: &mut Vec<SliceGuard>,
) {
    let Some(bound_var) = extract_some_or_ok_pat_ident(pat) else {
        return;
    };
    let Expr::MethodCall(mc) = unwrap_try_and_error_adapters(expr) else {
        return;
    };
    let method = mc.method.to_string();

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
    } else if matches!(method.as_str(), "find" | "rfind") {
        record_find_pattern_bounds_guards(&bound_var, mc, out);
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
    {
        record_chars_or_bytes_next_guards(&bound_var, inner_mc, out);
    }
}

fn record_find_pattern_bounds_guards(
    bound_var: &str,
    mc: &ExprMethodCall,
    out: &mut Vec<SliceGuard>,
) {
    let (recv_key, slice_start) = extract_receiver_and_slice_start(&mc.receiver);
    if recv_key.is_empty() {
        return;
    }
    let eff_pos = if let Some(sk) = &slice_start {
        let eff = format!("{sk}+{bound_var}");
        out.push(SliceGuard {
            collection: recv_key.clone(),
            index: Some(eff.clone()),
            min_len: 1,
            inclusive_upper_bound: false,
        });
        out.push(SliceGuard {
            collection: recv_key.clone(),
            index: Some(format!("{bound_var}+{sk}")),
            min_len: 1,
            inclusive_upper_bound: false,
        });
        eff
    } else {
        out.push(SliceGuard {
            collection: recv_key.clone(),
            index: Some(bound_var.to_string()),
            min_len: 1,
            inclusive_upper_bound: false,
        });
        bound_var.to_string()
    };

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

fn record_chars_or_bytes_next_guards(
    bound_var: &str,
    inner_mc: &ExprMethodCall,
    out: &mut Vec<SliceGuard>,
) {
    if !matches!(inner_mc.method.to_string().as_str(), "chars" | "bytes")
        || !inner_mc.args.is_empty()
    {
        return;
    }
    let recv_key = normalize_expr_key(&inner_mc.receiver);
    if recv_key.is_empty() {
        return;
    }
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

pub(super) fn extract_local_init_bounds_guards(
    var_name: &str,
    init_expr: &Expr,
    active_guards: &[SliceGuard],
    block_guards: &mut Vec<SliceGuard>,
) {
    let inner = unwrap_try_and_error_adapters(init_expr);
    if let Expr::MethodCall(mc) = inner
        && try_extract_method_local_init_guards(var_name, mc, block_guards)
    {
        return;
    }
    if let Expr::Binary(bin) = inner
        && extract_binary_local_init_guards(var_name, bin, block_guards)
    {
        return;
    }

    let expr_key = normalize_expr_key(init_expr);
    if !expr_key.is_empty() {
        let derived = derive_aliased_guards(var_name, &expr_key, active_guards, block_guards);
        block_guards.extend(derived);
    }
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

fn extract_take_while_count_coll(mc: &ExprMethodCall) -> Option<String> {
    if !mc.args.is_empty() {
        return None;
    }
    let Expr::MethodCall(tw_mc) = unwrap_paren_group(&mc.receiver) else {
        return None;
    };
    (tw_mc.method == "take_while")
        .then(|| extract_iter_receiver(&tw_mc.receiver))
        .flatten()
}

fn extract_find_unwrap_or_len_coll(mc: &ExprMethodCall) -> Option<String> {
    if mc.args.len() != 1 {
        return None;
    }
    let coll = extract_len_receiver(mc.args.first()?)?;
    let Expr::MethodCall(inner_mc) = unwrap_paren_group(&mc.receiver) else {
        return None;
    };
    (matches!(inner_mc.method.to_string().as_str(), "find" | "rfind")
        && normalize_expr_key(&inner_mc.receiver) == coll)
        .then_some(coll)
}

fn try_extract_method_local_init_guards(
    var_name: &str,
    mc: &ExprMethodCall,
    block_guards: &mut Vec<SliceGuard>,
) -> bool {
    let method = mc.method.to_string();
    if method == "min"
        && mc.args.len() == 1
        && let Some(arg) = mc.args.first()
        && let Some((coll, is_strict_lt)) = extract_len_or_saturating_sub_receiver(&mc.receiver)
            .or_else(|| extract_len_or_saturating_sub_receiver(arg))
    {
        block_guards.push(SliceGuard {
            collection: coll,
            index: Some(var_name.to_string()),
            min_len: 0,
            inclusive_upper_bound: !is_strict_lt,
        });
        return true;
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
            return true;
        }
    }
    if matches!(method.as_str(), "find" | "rfind") {
        extract_find_local_init_guards(var_name, mc, block_guards);
        return true;
    }
    let inclusive_coll = if method == "count" {
        extract_take_while_count_coll(mc)
    } else if method == "unwrap_or" {
        extract_find_unwrap_or_len_coll(mc)
    } else {
        None
    };
    if let Some(coll) = inclusive_coll {
        block_guards.push(SliceGuard {
            collection: coll,
            index: Some(var_name.to_string()),
            min_len: 0,
            inclusive_upper_bound: true,
        });
        return true;
    }
    false
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
        reason = "Only Some(ident) and Ok(ident) tuple-struct patterns bind single result values (#50)"
    )]
    match pat {
        Pat::TupleStruct(ts) => {
            let seg = ts.path.segments.last()?.ident.to_string();
            if matches!(seg.as_str(), "Some" | "Ok") && ts.elems.len() == 1 {
                ts.elems.first().and_then(extract_pat_ident)
            } else {
                None
            }
        }
        _ => None,
    }
}

pub(super) fn unwrap_try_and_error_adapters(expr: &Expr) -> &Expr {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Unwraps paren, group, reference, `?`, and error-adapter method calls (#50)"
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
        && mc.args.first().is_some_and(|a| normalize_expr_key(a) == "1")
        && let Some(coll) = extract_len_receiver(&mc.receiver)
    {
        return Some((coll, true));
    }
    None
}

pub(super) fn extract_while_body_reassignment_guards(
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
        propagate_assign_guards(assign, cond_guards, block_guards);
    } else if let Stmt::Expr(Expr::Binary(bin), _) = stmt
        && matches!(bin.op, BinOp::SubAssign(_))
    {
        tighten_sub_assign_guards(bin, block_guards);
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

fn propagate_assign_guards(
    assign: &syn::ExprAssign,
    extra_guards: &[SliceGuard],
    block_guards: &mut Vec<SliceGuard>,
) {
    let lhs_key = normalize_expr_key(&assign.left);
    let rhs_key = normalize_expr_key(&assign.right);
    if lhs_key.is_empty() || rhs_key.is_empty() {
        return;
    }
    let derived: Vec<SliceGuard> = extra_guards
        .iter()
        .chain(block_guards.iter())
        .filter(|g| !g.collection.is_empty() && g.index.as_deref() == Some(rhs_key.as_str()))
        .map(|g| SliceGuard {
            collection: g.collection.clone(),
            index: Some(lhs_key.clone()),
            min_len: g.min_len,
            inclusive_upper_bound: g.inclusive_upper_bound,
        })
        .collect();
    block_guards.extend(derived);
}

fn tighten_sub_assign_guards(bin: &ExprBinary, block_guards: &mut [SliceGuard]) {
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

pub(super) fn extract_post_stmt_bounds_guards(stmt: &Stmt, block_guards: &mut Vec<SliceGuard>) {
    match stmt {
        Stmt::Expr(Expr::If(expr_if), _) if block_always_diverges(&expr_if.then_branch) => {
            extract_cond_bounds_guards(&expr_if.cond, true, block_guards);
        }
        Stmt::Expr(Expr::Assign(assign), _) => {
            propagate_assign_guards(assign, &[], block_guards);
        }
        Stmt::Expr(Expr::Binary(bin), _) if matches!(bin.op, BinOp::SubAssign(_)) => {
            tighten_sub_assign_guards(bin, block_guards);
        }
        Stmt::Macro(stmt_macro) if stmt_macro.mac.path.is_ident("assert") => {
            if let Ok(cond_expr) = syn::parse2::<Expr>(stmt_macro.mac.tokens.clone()) {
                extract_cond_bounds_guards(&cond_expr, false, block_guards);
            }
        }
        Stmt::Local(_) | Stmt::Item(_) | Stmt::Expr(..) | Stmt::Macro(_) => {}
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
