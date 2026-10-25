//! Helper predicates, guard extractors, and autofix builders for Python runtime safety rules.

use std::collections::HashSet;

use dotore_core::{AutofixPatch, ByteEdit, ByteSpan, loc_from_line_starts};
use ruff_python_ast::{CmpOp, Expr, Stmt, UnaryOp};
use ruff_text_size::Ranged;

use crate::matchers::{callee_qualified_name, slice_source, text_range_to_byte_span};

pub(super) fn is_ellipsis_only_body(body: &[Stmt]) -> bool {
    matches!(
        body,
        [Stmt::Expr(expr_stmt)] if matches!(expr_stmt.value.as_ref(), Expr::EllipsisLiteral(_))
    )
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Matches only bare or broad Exception/BaseException names and tuples (#50)"
)]
pub(super) fn expr_contains_broad_exception(expr: &Expr) -> bool {
    match expr {
        Expr::Name(n) => matches!(n.id.as_str(), "Exception" | "BaseException"),
        Expr::Attribute(attr) => matches!(attr.attr.as_str(), "Exception" | "BaseException"),
        Expr::Tuple(t) => t.elts.iter().any(expr_contains_broad_exception),
        _ => false,
    }
}

pub(super) fn is_fallback_try_stmt(stmt: &Stmt) -> bool {
    let Stmt::Try(try_stmt) = stmt else {
        return false;
    };
    !try_stmt.handlers.is_empty()
        && try_stmt.handlers.iter().all(|handler| {
            let ruff_python_ast::ExceptHandler::ExceptHandler(h) = handler;
            !h.body.is_empty()
                && h.body
                    .iter()
                    .all(|s| matches!(s, Stmt::Pass(_) | Stmt::Continue(_)))
        })
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only pass, loop continue, and literal/ellipsis expression statements count as silent no-op bodies (#50)"
)]
pub(super) fn is_silent_handler_body(body: &[Stmt], in_loop: bool) -> bool {
    !body.is_empty()
        && body.iter().all(|stmt| match stmt {
            Stmt::Pass(_) => true,
            Stmt::Continue(_) => in_loop,
            Stmt::Expr(expr_stmt) => matches!(
                expr_stmt.value.as_ref(),
                Expr::EllipsisLiteral(_)
                    | Expr::StringLiteral(_)
                    | Expr::BytesLiteral(_)
                    | Expr::NumberLiteral(_)
                    | Expr::BooleanLiteral(_)
                    | Expr::NoneLiteral(_)
            ),
            _ => false,
        })
}

pub(super) fn is_resource_acquisition_callee(callee: &str, func_expr: &Expr) -> bool {
    if matches!(
        callee,
        "open"
            | "io.open"
            | "codecs.open"
            | "builtins.open"
            | "tempfile.NamedTemporaryFile"
            | "NamedTemporaryFile"
            | "tempfile.TemporaryFile"
            | "TemporaryFile"
            | "sqlite3.connect"
            | "psycopg2.connect"
            | "psycopg.connect"
            | "asyncpg.connect"
            | "pymysql.connect"
            | "aiomysql.connect"
            | "mysql.connector.connect"
            | "sqlalchemy.orm.Session"
            | "Session"
            | "AsyncSession"
            | "SessionLocal"
            | "AsyncSessionLocal"
    ) {
        return true;
    }
    if let Expr::Attribute(attr) = func_expr {
        let method = attr.attr.as_str();
        let recv = callee_qualified_name(&attr.value);
        if matches!(method, "connect" | "begin")
            && matches!(
                recv.as_str(),
                "engine" | "db_engine" | "async_engine" | "self.engine"
            )
        {
            return true;
        }
        if method == "open"
            && (recv.starts_with("Path")
                || recv.starts_with("pathlib.Path")
                || recv.ends_with("_path")
                || recv.ends_with("_file")
                || recv == "path")
        {
            return true;
        }
    }
    false
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Scans compound statements in a scope for try...finally blocks that call .close() / .aclose() (#50)"
)]
pub(super) fn collect_finally_closed_vars(suite: &[Stmt]) -> HashSet<String> {
    let mut closed = HashSet::new();
    for stmt in suite {
        match stmt {
            Stmt::Try(try_stmt) => {
                collect_close_calls_in_suite(&try_stmt.finalbody, &mut closed);
                closed.extend(collect_finally_closed_vars(&try_stmt.body));
            }
            Stmt::If(if_stmt) => {
                closed.extend(collect_finally_closed_vars(&if_stmt.body));
                for clause in &if_stmt.elif_else_clauses {
                    closed.extend(collect_finally_closed_vars(&clause.body));
                }
            }
            Stmt::With(with_stmt) => {
                closed.extend(collect_finally_closed_vars(&with_stmt.body));
            }
            _ => {}
        }
    }
    closed
}

fn collect_close_calls_in_suite(suite: &[Stmt], out: &mut HashSet<String>) {
    for stmt in suite {
        if let Stmt::Expr(expr_stmt) = stmt {
            let inner = if let Expr::Await(aw) = expr_stmt.value.as_ref() {
                aw.value.as_ref()
            } else {
                expr_stmt.value.as_ref()
            };
            if let Expr::Call(call) = inner
                && let Expr::Attribute(attr) = call.func.as_ref()
                && matches!(attr.attr.as_str(), "close" | "aclose")
                && let Expr::Name(n) = attr.value.as_ref()
            {
                out.insert(n.id.to_string());
            }
        }
    }
}

pub(super) fn collect_caught_exceptions(
    handlers: &[ruff_python_ast::ExceptHandler],
) -> HashSet<String> {
    let mut caught = HashSet::new();
    for handler in handlers {
        let ruff_python_ast::ExceptHandler::ExceptHandler(h) = handler;
        match h.type_.as_deref() {
            None => {
                caught.insert("BaseException".to_string());
                caught.insert("Exception".to_string());
            }
            Some(type_expr) => collect_exception_names_from_expr(type_expr, &mut caught),
        }
    }
    caught
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Extracts exception identifiers from Name, Attribute, and Tuple AST nodes (#50)"
)]
fn collect_exception_names_from_expr(expr: &Expr, out: &mut HashSet<String>) {
    match expr {
        Expr::Name(n) => {
            out.insert(n.id.to_string());
        }
        Expr::Attribute(attr) => {
            out.insert(attr.attr.to_string());
        }
        Expr::Tuple(t) => {
            for elt in &t.elts {
                collect_exception_names_from_expr(elt, out);
            }
        }
        _ => {}
    }
}

#[expect(
    clippy::type_complexity,
    clippy::wildcard_enum_match_arm,
    reason = "Extracts positive and negative numeric and dict-membership guards from an if condition (#50)"
)]
pub(super) fn extract_if_guards(
    source: &str,
    test: &Expr,
) -> (
    HashSet<String>,
    HashSet<(String, String)>,
    HashSet<String>,
    HashSet<(String, String)>,
) {
    let mut pos_num = HashSet::new();
    let mut pos_keys = HashSet::new();
    let mut neg_num = HashSet::new();
    let mut neg_keys = HashSet::new();

    match test {
        Expr::Call(call) => {
            if let Expr::Attribute(attr) = call.func.as_ref()
                && matches!(attr.attr.as_str(), "isdigit" | "isnumeric" | "isdecimal")
                && let Expr::Name(n) = attr.value.as_ref()
            {
                pos_num.insert(n.id.to_string());
            } else if matches!(callee_qualified_name(&call.func).as_str(), "isinstance")
                && let Some(Expr::Name(n)) = call.arguments.args.first()
            {
                pos_num.insert(n.id.to_string());
            }
        }
        Expr::Compare(cmp) => {
            if let (Some(op), Some(right)) = (cmp.ops.first(), cmp.comparators().first()) {
                let full_text = slice_source(source, text_range_to_byte_span(cmp.range()));
                let left_text = extract_in_left_operand(full_text);
                let right_name = callee_qualified_name(right);
                if !left_text.is_empty() && !right_name.is_empty() {
                    match op {
                        CmpOp::In => {
                            pos_keys.insert((right_name, left_text.to_string()));
                        }
                        CmpOp::NotIn => {
                            neg_keys.insert((right_name, left_text.to_string()));
                        }
                        _ => {}
                    }
                }
            }
        }
        Expr::UnaryOp(un) if un.op == UnaryOp::Not => {
            let (inner_pos_num, inner_pos_keys, inner_neg_num, inner_neg_keys) =
                extract_if_guards(source, &un.operand);
            pos_num.extend(inner_neg_num);
            pos_keys.extend(inner_neg_keys);
            neg_num.extend(inner_pos_num);
            neg_keys.extend(inner_pos_keys);
        }
        Expr::BoolOp(bool_op) => {
            for val in &bool_op.values {
                let (p_num, p_keys, n_num, n_keys) = extract_if_guards(source, val);
                pos_num.extend(p_num);
                pos_keys.extend(p_keys);
                neg_num.extend(n_num);
                neg_keys.extend(n_keys);
            }
        }
        _ => {}
    }

    (pos_num, pos_keys, neg_num, neg_keys)
}

fn extract_in_left_operand(compare_text: &str) -> &str {
    if let Some((left, _)) = compare_text.split_once(" not in ") {
        return left.trim();
    }
    if let Some((left, _)) = compare_text.split_once(" in ") {
        return left.trim();
    }
    ""
}

pub(super) fn suite_terminates_early(suite: &[Stmt]) -> bool {
    matches!(
        suite.last(),
        Some(Stmt::Return(_) | Stmt::Raise(_) | Stmt::Continue(_) | Stmt::Break(_))
    )
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Checks whether an int()/float() argument is a known-safe literal or numeric expression (#50)"
)]
pub(super) fn is_safe_numeric_parse_arg(expr: &Expr) -> bool {
    match expr {
        Expr::NumberLiteral(_) | Expr::BooleanLiteral(_) => true,
        Expr::StringLiteral(s) => {
            let text = s.value.to_str().trim();
            text.parse::<i128>().is_ok() || text.parse::<f64>().is_ok()
        }
        Expr::UnaryOp(un)
            if matches!(un.op, UnaryOp::USub | UnaryOp::UAdd)
                && is_safe_numeric_parse_arg(&un.operand) =>
        {
            true
        }
        Expr::Call(call) => matches!(
            callee_qualified_name(&call.func).as_str(),
            "len" | "abs" | "round" | "min" | "max" | "sum"
        ),
        _ => false,
    }
}

pub(super) fn is_typing_generic_receiver(recv: &str) -> bool {
    let tail = recv.rsplit('.').next().unwrap_or(recv);
    matches!(
        tail,
        "dict"
            | "list"
            | "set"
            | "frozenset"
            | "tuple"
            | "type"
            | "Dict"
            | "List"
            | "Set"
            | "FrozenSet"
            | "Tuple"
            | "Type"
            | "Optional"
            | "Union"
            | "Literal"
            | "Annotated"
            | "Callable"
            | "Sequence"
            | "MutableSequence"
            | "Mapping"
            | "MutableMapping"
            | "Iterable"
            | "Iterator"
            | "AsyncIterator"
            | "AsyncIterable"
            | "Generator"
            | "AsyncGenerator"
            | "Awaitable"
            | "Coroutine"
            | "ClassVar"
            | "Final"
            | "Generic"
            | "Protocol"
    ) || tail.chars().next().is_some_and(|c| c.is_ascii_uppercase())
}

pub(super) fn is_dict_or_external_mapping_receiver(recv: &str) -> bool {
    matches!(
        recv,
        "os.environ"
            | "environ"
            | "payload"
            | "data"
            | "body"
            | "json_body"
            | "params"
            | "query"
            | "query_params"
            | "headers"
            | "cookies"
            | "row"
            | "record"
            | "event"
            | "config"
            | "settings"
            | "kwargs"
            | "context"
            | "meta"
            | "metadata"
            | "response"
            | "res"
            | "req"
            | "request"
    ) || recv.starts_with("request.")
        || recv.starts_with("req.")
        || recv.ends_with(".headers")
        || recv.ends_with(".cookies")
        || recv.ends_with(".query_params")
        || recv.ends_with(".path_params")
        || recv.ends_with(".environ")
}

#[expect(
    clippy::wildcard_enum_match_arm,
    reason = "Only mutable collection literals, comprehensions, and mutable collection constructors are flagged (#50)"
)]
pub(super) fn is_mutable_default_expr(expr: &Expr) -> bool {
    match expr {
        Expr::List(_)
        | Expr::Dict(_)
        | Expr::Set(_)
        | Expr::ListComp(_)
        | Expr::DictComp(_)
        | Expr::SetComp(_) => true,
        Expr::Call(call) => {
            let callee = callee_qualified_name(&call.func);
            matches!(
                callee.as_str(),
                "list"
                    | "dict"
                    | "set"
                    | "bytearray"
                    | "deque"
                    | "collections.deque"
                    | "defaultdict"
                    | "collections.defaultdict"
                    | "OrderedDict"
                    | "collections.OrderedDict"
                    | "Counter"
                    | "collections.Counter"
                    | "ChainMap"
                    | "collections.ChainMap"
            )
        }
        _ => false,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Autofix builder takes parsed body, line table, and parameter metadata directly (#50)"
)]
pub(super) fn build_mutable_default_autofix(
    _source: &str,
    lines: &[&str],
    line_starts: &[u32],
    body: &[Stmt],
    signature_end_line: u32,
    param_name: &str,
    default_span: ByteSpan,
    default_text: &str,
) -> Option<AutofixPatch> {
    let first_stmt = body.first()?;
    let is_first_docstring = matches!(
        first_stmt,
        Stmt::Expr(expr_stmt) if matches!(expr_stmt.value.as_ref(), Expr::StringLiteral(_))
    );
    let target_stmt = if is_first_docstring {
        body.get(1).unwrap_or(first_stmt)
    } else {
        first_stmt
    };

    let stmt_span = text_range_to_byte_span(target_stmt.range());
    let stmt_loc = loc_from_line_starts(line_starts, stmt_span.start);
    if stmt_loc.line <= signature_end_line {
        return None;
    }
    let stmt_line = lines.get((stmt_loc.line - 1) as usize).copied()?;
    let indent_len = stmt_line.len() - stmt_line.trim_start().len();
    let body_indent = stmt_line.get(..indent_len).unwrap_or("");

    let (insert_pos, guard_replacement) = if is_first_docstring && body.len() == 1 {
        let end_pos = stmt_span.end;
        (
            end_pos,
            format!(
                "\n{body_indent}if {param_name} is None:\n{body_indent}    {param_name} = {default_text}"
            ),
        )
    } else {
        let insert_pos = stmt_span.start;
        (
            insert_pos,
            format!(
                "if {param_name} is None:\n{body_indent}    {param_name} = {default_text}\n{body_indent}"
            ),
        )
    };

    Some(
        AutofixPatch::new(format!(
            "Replace mutable default `{default_text}` on `{param_name}` with `None` and initialize inside function body"
        ))
        .with_byte_edit(ByteEdit::replace(default_span, "None"))
        .with_byte_edit(ByteEdit::insert(insert_pos, guard_replacement)),
    )
}
