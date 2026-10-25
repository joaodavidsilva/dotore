//! Numeric type inference, lossy `as` cast detection, `unsafe` `// SAFETY:` comment
//! inspection, and `std::mem::forget` helpers for `safety.rs`.

use syn::{BinOp, Expr, ExprCall, Lit, Pat, Type, UnOp, UseTree};

use crate::matchers::{extract_pat_ident, extract_type_name, path_to_string};

use super::{SafetyVisitor, bounds:: unwrap_paren_group};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum NumericType {
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
    pub(super) fn from_type_name(name: &str) -> Option<Self> {
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

    pub(super) const fn is_float(self) -> bool {
        matches!(self, Self::F32 | Self::F64)
    }

    pub(super) const fn is_signed_int(self) -> bool {
        matches!(
            self,
            Self::I8 | Self::I16 | Self::I32 | Self::I64 | Self::I128 | Self::Isize
        )
    }

    pub(super) const fn is_unsigned_int(self) -> bool {
        matches!(
            self,
            Self::U8 | Self::U16 | Self::U32 | Self::U64 | Self::U128 | Self::Usize
        )
    }

    pub(super) const fn bit_width_rank(self) -> u8 {
        match self {
            Self::Bool | Self::U8 | Self::I8 => 8,
            Self::U16 | Self::I16 => 16,
            Self::Char | Self::U32 | Self::I32 | Self::F32 => 32,
            Self::Usize | Self::Isize => 48,
            Self::U64 | Self::I64 | Self::F64 => 64,
            Self::U128 | Self::I128 | Self::UnsuffixedInt(_) => 128,
        }
    }
}

impl SafetyVisitor<'_> {
    pub(super) fn infer_expr_numeric_type(&self, expr: &Expr) -> Option<NumericType> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "syn::Expr has dozens of variants; delegates compound numeric expressions (#50)"
        )]
        match unwrap_paren_group(expr) {
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
            Expr::Lit(expr_lit) => infer_lit_numeric_type(&expr_lit.lit),
            other => self.infer_compound_expr_numeric_type(other),
        }
    }

    fn infer_compound_expr_numeric_type(&self, expr: &Expr) -> Option<NumericType> {
        #[expect(
            clippy::wildcard_enum_match_arm,
            reason = "Compound numeric inference handles unary, binary, call, method-call, and cast (#50)"
        )]
        match expr {
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
            Expr::Call(expr_call) => infer_call_numeric_type(expr_call),
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

    pub(super) fn has_safety_comment_near(&self, start_line: u32, end_line: u32) -> bool {
        if start_line == 0 || self.lines.is_empty() {
            return false;
        }
        let start_idx = usize::try_from(start_line - 1).unwrap_or(0);
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
}

fn infer_lit_numeric_type(lit: &Lit) -> Option<NumericType> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "Only numeric, byte, bool, and char literals map to NumericType (#50)"
    )]
    match lit {
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
            if lit_float.suffix() == "f32" {
                Some(NumericType::F32)
            } else {
                Some(NumericType::F64)
            }
        }
        Lit::Byte(_) => Some(NumericType::U8),
        Lit::Bool(_) => Some(NumericType::Bool),
        Lit::Char(_) => Some(NumericType::Char),
        _ => None,
    }
}

fn infer_call_numeric_type(expr_call: &ExprCall) -> Option<NumericType> {
    let Expr::Path(expr_path) = expr_call.func.as_ref() else {
        return None;
    };
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
    None
}

pub(super) fn use_tree_imports_mem_forget(tree: &UseTree, prefix: &str) -> bool {
    match tree {
        UseTree::Path(use_path) => {
            let next_prefix = if prefix.is_empty() {
                use_path.ident.to_string()
            } else {
                format!("{prefix}::{}", use_path.ident)
            };
            use_tree_imports_mem_forget(&use_path.tree, &next_prefix)
        }
        UseTree::Name(use_name) => is_qualified_mem_forget(prefix, &use_name.ident.to_string()),
        UseTree::Rename(use_rename) => {
            is_qualified_mem_forget(prefix, &use_rename.ident.to_string())
        }
        UseTree::Group(group) => group
            .items
            .iter()
            .any(|item| use_tree_imports_mem_forget(item, prefix)),
        UseTree::Glob(_) => matches!(prefix, "std::mem" | "core::mem"),
    }
}

fn is_qualified_mem_forget(prefix: &str, ident: &str) -> bool {
    let full = if prefix.is_empty() {
        ident.to_string()
    } else {
        format!("{prefix}::{ident}")
    };
    matches!(
        full.as_str(),
        "std::mem::forget" | "core::mem::forget" | "mem::forget"
    )
}

pub(super) fn is_mem_forget_path(path: &syn::Path, has_imported_mem_forget: bool) -> bool {
    let joined = path_to_string(path);
    matches!(
        joined.as_str(),
        "std::mem::forget" | "core::mem::forget" | "mem::forget"
    ) || (has_imported_mem_forget && joined == "forget")
}

pub(super) fn extract_numeric_type(ty: &Type) -> Option<NumericType> {
    let name = extract_type_name(ty)?;
    NumericType::from_type_name(&name)
}

pub(super) fn extract_local_ident_and_type(pat: &Pat) -> Option<(String, Option<NumericType>)> {
    #[expect(
        clippy::wildcard_enum_match_arm,
        reason = "syn::Pat has many variants; only ident and typed patterns bind a single local variable (#50)"
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

fn is_unsuffixed_int_cast_lossy(val: i128, target_ty: NumericType) -> bool {
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

fn is_typed_numeric_cast_lossy(src: NumericType, target_ty: NumericType) -> bool {
    if src == target_ty || matches!(src, NumericType::Bool | NumericType::Char) {
        return false;
    }
    if src.is_float() {
        return !matches!((src, target_ty), (NumericType::F32, NumericType::F64));
    }
    if target_ty.is_float() {
        return src.bit_width_rank() >= target_ty.bit_width_rank();
    }
    if src.is_signed_int() && target_ty.is_unsigned_int() {
        return true;
    }
    if src.is_unsigned_int() && target_ty.is_signed_int() {
        return src.bit_width_rank() >= target_ty.bit_width_rank();
    }
    src.bit_width_rank() > target_ty.bit_width_rank()
}

pub(super) fn is_lossy_or_sign_changing_cast(
    src_ty: Option<NumericType>,
    target_ty: NumericType,
) -> bool {
    match src_ty {
        Some(NumericType::UnsuffixedInt(val)) => is_unsuffixed_int_cast_lossy(val, target_ty),
        Some(src) => is_typed_numeric_cast_lossy(src, target_ty),
        None => matches!(
            target_ty,
            NumericType::U8
                | NumericType::U16
                | NumericType::U32
                | NumericType::I8
                | NumericType::I16
                | NumericType::I32
                | NumericType::Isize
        ),
    }
}

fn line_has_safety_comment(line: &str) -> bool {
    let Some(comment_pos) = line.find("//").or_else(|| line.find("/*")) else {
        return false;
    };
    let comment_part = line[comment_pos..].to_ascii_lowercase();
    comment_part.contains("safety:") || comment_part.contains("# safety")
}
