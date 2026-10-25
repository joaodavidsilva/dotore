//! Normalized structural FNV-1a AST hashing for Python helper functions.

use dotore_core::{FNV1A_64_OFFSET_BASIS, fnv1a_64_byte, fnv1a_64_str};
use ruff_python_ast::{BoolOp, CmpOp, Expr, ExprCall, Operator, Stmt, StmtFunctionDef, UnaryOp};

use super::facets::is_docstring_stmt;

pub(super) fn compute_function_structural_hash(
    func_def: &StmtFunctionDef,
    param_count: usize,
) -> u64 {
    let mut hash = FNV1A_64_OFFSET_BASIS;
    fnv1a_64_byte(&mut hash, u8::from(func_def.is_async));
    fnv1a_64_byte(&mut hash, u8::try_from(param_count).unwrap_or(u8::MAX));
    let body_without_docstring = match func_def.body.split_first() {
        Some((first, rest)) if is_docstring_stmt(first) => rest,
        _ => &func_def.body,
    };
    hash_suite(&mut hash, body_without_docstring);
    hash
}

fn hash_suite(hash: &mut u64, suite: &[Stmt]) {
    for stmt in suite {
        hash_stmt(hash, stmt);
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Hashes structural Python AST statement variants normalized across local variable names (#50)"
)]
fn hash_stmt(hash: &mut u64, stmt: &Stmt) {
    match stmt {
        Stmt::Assign(assign) => {
            fnv1a_64_str(hash, "Stmt::Assign");
            for target in &assign.targets {
                hash_assign_target_shape(hash, target);
            }
            hash_expr(hash, &assign.value);
        }
        Stmt::AnnAssign(ann) => {
            if let Some(val) = &ann.value {
                fnv1a_64_str(hash, "Stmt::Assign");
                hash_assign_target_shape(hash, &ann.target);
                hash_expr(hash, val);
            } else {
                fnv1a_64_str(hash, "Stmt::AnnDecl");
            }
        }
        Stmt::AugAssign(aug) => {
            fnv1a_64_str(hash, "Stmt::AugAssign");
            hash_assign_target_shape(hash, &aug.target);
            hash_operator(hash, aug.op);
            hash_expr(hash, &aug.value);
        }
        Stmt::Return(ret) => {
            fnv1a_64_str(hash, "Stmt::Return");
            if let Some(val) = &ret.value {
                hash_expr(hash, val);
            }
        }
        Stmt::Expr(expr_stmt) => {
            fnv1a_64_str(hash, "Stmt::Expr");
            hash_expr(hash, &expr_stmt.value);
        }
        Stmt::Raise(r) => {
            fnv1a_64_str(hash, "Stmt::Raise");
            if let Some(exc) = &r.exc {
                hash_expr(hash, exc);
            }
        }
        Stmt::Break(_) => fnv1a_64_str(hash, "Stmt::Break"),
        Stmt::Continue(_) => fnv1a_64_str(hash, "Stmt::Continue"),
        Stmt::Pass(_) => fnv1a_64_str(hash, "Stmt::Pass"),
        _ => hash_compound_stmt(hash, stmt),
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Hashes compound Python statement variants (#50)"
)]
fn hash_compound_stmt(hash: &mut u64, stmt: &Stmt) {
    match stmt {
        Stmt::If(if_stmt) => {
            fnv1a_64_str(hash, "Stmt::If");
            hash_expr(hash, &if_stmt.test);
            hash_suite(hash, &if_stmt.body);
            for clause in &if_stmt.elif_else_clauses {
                fnv1a_64_str(hash, "Stmt::ElifElse");
                if let Some(t) = &clause.test {
                    hash_expr(hash, t);
                }
                hash_suite(hash, &clause.body);
            }
        }
        Stmt::For(for_stmt) => {
            fnv1a_64_str(hash, "Stmt::For");
            hash_assign_target_shape(hash, &for_stmt.target);
            hash_expr(hash, &for_stmt.iter);
            hash_suite(hash, &for_stmt.body);
            hash_suite(hash, &for_stmt.orelse);
        }
        Stmt::While(while_stmt) => {
            fnv1a_64_str(hash, "Stmt::While");
            hash_expr(hash, &while_stmt.test);
            hash_suite(hash, &while_stmt.body);
            hash_suite(hash, &while_stmt.orelse);
        }
        Stmt::With(with_stmt) => {
            fnv1a_64_str(hash, "Stmt::With");
            for item in &with_stmt.items {
                hash_expr(hash, &item.context_expr);
            }
            hash_suite(hash, &with_stmt.body);
        }
        Stmt::Try(try_stmt) => {
            fnv1a_64_str(hash, "Stmt::Try");
            hash_suite(hash, &try_stmt.body);
            for ruff_python_ast::ExceptHandler::ExceptHandler(handler) in &try_stmt.handlers {
                fnv1a_64_str(hash, "Stmt::Except");
                hash_suite(hash, &handler.body);
            }
            hash_suite(hash, &try_stmt.orelse);
            hash_suite(hash, &try_stmt.finalbody);
        }
        _ => fnv1a_64_str(hash, "Stmt::Other"),
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Hashes target shape for assignments and loop variables (#50)"
)]
fn hash_assign_target_shape(hash: &mut u64, target: &Expr) {
    match target {
        Expr::Name(_) => fnv1a_64_str(hash, "Target::Name"),
        Expr::Subscript(s) => {
            fnv1a_64_str(hash, "Target::Subscript");
            hash_expr(hash, &s.value);
            hash_expr(hash, &s.slice);
        }
        Expr::Attribute(a) => {
            fnv1a_64_str(hash, "Target::Attr");
            fnv1a_64_str(hash, a.attr.as_str());
            hash_expr(hash, &a.value);
        }
        Expr::Tuple(t) => {
            fnv1a_64_str(hash, "Target::Tuple");
            fnv1a_64_byte(hash, u8::try_from(t.elts.len()).unwrap_or(u8::MAX));
            for elt in &t.elts {
                hash_assign_target_shape(hash, elt);
            }
        }
        _ => fnv1a_64_str(hash, "Target::Other"),
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Hashes structural Python AST expressions normalized over local identifier names (#50)"
)]
fn hash_expr(hash: &mut u64, expr: &Expr) {
    match expr {
        Expr::Name(_) => fnv1a_64_str(hash, "Expr::Name"),
        Expr::Attribute(attr) => {
            fnv1a_64_str(hash, "Expr::Attr");
            fnv1a_64_str(hash, attr.attr.as_str());
            hash_expr(hash, &attr.value);
        }
        Expr::Call(call) => hash_call_expr(hash, call),
        Expr::BinOp(b) => {
            fnv1a_64_str(hash, "Expr::BinOp");
            hash_operator(hash, b.op);
            hash_expr(hash, &b.left);
            hash_expr(hash, &b.right);
        }
        Expr::UnaryOp(u) => {
            fnv1a_64_str(hash, "Expr::UnaryOp");
            hash_unary_op(hash, u.op);
            hash_expr(hash, &u.operand);
        }
        Expr::BoolOp(b) => {
            fnv1a_64_str(hash, "Expr::BoolOp");
            fnv1a_64_str(hash, if matches!(b.op, BoolOp::And) { "And" } else { "Or" });
            for v in &b.values {
                hash_expr(hash, v);
            }
        }
        Expr::Compare(cmp) => {
            fnv1a_64_str(hash, "Expr::Compare");
            for op in &cmp.ops {
                hash_cmp_op(hash, *op);
            }
            for operand in &cmp.operands {
                hash_expr(hash, operand);
            }
        }
        Expr::Subscript(s) => {
            fnv1a_64_str(hash, "Expr::Subscript");
            hash_expr(hash, &s.value);
            hash_expr(hash, &s.slice);
        }
        Expr::If(if_expr) => {
            fnv1a_64_str(hash, "Expr::If");
            hash_expr(hash, &if_expr.test);
            hash_expr(hash, &if_expr.body);
            hash_expr(hash, &if_expr.orelse);
        }
        Expr::Await(aw) => {
            fnv1a_64_str(hash, "Expr::Await");
            hash_expr(hash, &aw.value);
        }
        _ => hash_collection_or_literal_expr(hash, expr),
    }
}

fn hash_call_expr(hash: &mut u64, call: &ExprCall) {
    fnv1a_64_str(hash, "Expr::Call");
    if let Expr::Name(n) = call.func.as_ref() {
        fnv1a_64_str(hash, n.id.as_str());
    } else {
        hash_expr(hash, &call.func);
    }
    fnv1a_64_byte(
        hash,
        u8::try_from(call.arguments.args.len()).unwrap_or(u8::MAX),
    );
    fnv1a_64_byte(
        hash,
        u8::try_from(call.arguments.keywords.len()).unwrap_or(u8::MAX),
    );
    for arg in &call.arguments.args {
        hash_expr(hash, arg);
    }
    for kw in &call.arguments.keywords {
        if let Some(k) = &kw.arg {
            fnv1a_64_str(hash, k.as_str());
        }
        hash_expr(hash, &kw.value);
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Hashes collection, comprehension, and literal Python expressions (#50)"
)]
fn hash_collection_or_literal_expr(hash: &mut u64, expr: &Expr) {
    match expr {
        Expr::List(l) => hash_expr_slice(hash, "Expr::List", &l.elts),
        Expr::Tuple(t) => hash_expr_slice(hash, "Expr::Tuple", &t.elts),
        Expr::Set(s) => hash_expr_slice(hash, "Expr::Set", &s.elts),
        Expr::Dict(d) => {
            fnv1a_64_str(hash, "Expr::Dict");
            fnv1a_64_byte(hash, u8::try_from(d.items.len()).unwrap_or(u8::MAX));
            for item in &d.items {
                if let Some(k) = &item.key {
                    hash_expr(hash, k);
                }
                hash_expr(hash, &item.value);
            }
        }
        Expr::ListComp(comp) => {
            hash_comprehension_expr(hash, "Expr::ListComp", None, &comp.elt, &comp.generators);
        }
        Expr::SetComp(comp) => {
            hash_comprehension_expr(hash, "Expr::SetComp", None, &comp.elt, &comp.generators);
        }
        Expr::DictComp(comp) => {
            hash_comprehension_expr(
                hash,
                "Expr::DictComp",
                comp.key.as_deref(),
                &comp.value,
                &comp.generators,
            );
        }
        _ => hash_literal_expr(hash, expr),
    }
}

fn hash_expr_slice(hash: &mut u64, tag: &str, elts: &[Expr]) {
    fnv1a_64_str(hash, tag);
    fnv1a_64_byte(hash, u8::try_from(elts.len()).unwrap_or(u8::MAX));
    for e in elts {
        hash_expr(hash, e);
    }
}

fn hash_comprehension_expr(
    hash: &mut u64,
    tag: &str,
    key: Option<&Expr>,
    elt: &Expr,
    generators: &[ruff_python_ast::Comprehension],
) {
    fnv1a_64_str(hash, tag);
    if let Some(k) = key {
        hash_expr(hash, k);
    }
    hash_expr(hash, elt);
    for g in generators {
        hash_expr(hash, &g.iter);
        for cond in &g.ifs {
            hash_expr(hash, cond);
        }
    }
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Hashes literal Python expression nodes (#50)"
)]
fn hash_literal_expr(hash: &mut u64, expr: &Expr) {
    match expr {
        Expr::StringLiteral(s) => {
            fnv1a_64_str(hash, "Expr::Str");
            fnv1a_64_str(hash, s.value.to_str());
        }
        Expr::FString(fstr) => {
            fnv1a_64_str(hash, "Expr::FString");
            for part in fstr.value.elements() {
                if let Some(lit) = part.as_literal() {
                    fnv1a_64_str(hash, &lit.value);
                } else if let Some(interp) = part.as_interpolation() {
                    hash_expr(hash, &interp.expression);
                }
            }
        }
        Expr::NumberLiteral(_) => fnv1a_64_str(hash, "Expr::Num"),
        Expr::BooleanLiteral(b) => {
            fnv1a_64_str(hash, "Expr::Bool");
            fnv1a_64_byte(hash, u8::from(b.value));
        }
        Expr::NoneLiteral(_) => fnv1a_64_str(hash, "Expr::None"),
        _ => fnv1a_64_str(hash, "Expr::Other"),
    }
}

fn hash_operator(hash: &mut u64, op: Operator) {
    let label = match op {
        Operator::Add => "+",
        Operator::Sub => "-",
        Operator::Mult => "*",
        Operator::MatMult => "@",
        Operator::Div => "/",
        Operator::Mod => "%",
        Operator::Pow => "**",
        Operator::LShift => "<<",
        Operator::RShift => ">>",
        Operator::BitOr => "|",
        Operator::BitXor => "^",
        Operator::BitAnd => "&",
        Operator::FloorDiv => "//",
    };
    fnv1a_64_str(hash, label);
}

fn hash_unary_op(hash: &mut u64, op: UnaryOp) {
    let label = match op {
        UnaryOp::Invert => "~",
        UnaryOp::Not => "not",
        UnaryOp::UAdd => "+u",
        UnaryOp::USub => "-u",
    };
    fnv1a_64_str(hash, label);
}

fn hash_cmp_op(hash: &mut u64, op: CmpOp) {
    let label = match op {
        CmpOp::Eq => "==",
        CmpOp::NotEq => "!=",
        CmpOp::Lt => "<",
        CmpOp::LtE => "<=",
        CmpOp::Gt => ">",
        CmpOp::GtE => ">=",
        CmpOp::Is => "is",
        CmpOp::IsNot => "is not",
        CmpOp::In => "in",
        CmpOp::NotIn => "not in",
    };
    fnv1a_64_str(hash, label);
}
