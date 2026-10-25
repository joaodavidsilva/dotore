//! Entrypoint, UI kit, statement count, static catalog, I/O call, and terminal literal classifiers for [`super`].
#![expect(
    clippy::wildcard_enum_match_arm,
    reason = "oxc_ast AST enums have 200+ variants; SoC classifiers match only relevant node kinds (#50)"
)]

use std::{collections::BTreeSet, path::Path};

use oxc_ast::{
    AstKind,
    ast::{
        ArrayExpressionElement, BindingPattern, CallExpression, Expression, ObjectPropertyKind,
        Program, Statement,
    },
};
use oxc_semantic::{NodeId, Semantic};
use oxc_span::Span;

use crate::ir::{
    ArchitectureFileFacets, ByteSpan, ConcernBucket, JsxElementIr, StaticCatalogSiteIr,
    SymbolKind, SymbolOutline, TerminalUiPrimitiveKind, loc_from_line_starts, types::ModuleIr,
};

use super::{DEFAULT_SIGNAL_CATALOG_ENTRIES, MIN_CANDIDATE_CATALOG_ENTRIES, push_concern_signal};

pub(super) const fn spans_contain(outer: ByteSpan, inner: ByteSpan) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

pub(super) const fn spans_overlap(a: ByteSpan, b: ByteSpan) -> bool {
    a.start < b.end && b.start < a.end
}

pub(super) fn is_js_entrypoint_path(path: &Path, source: &str, module: &ModuleIr) -> bool {
    if module.is_aggregation_barrel {
        return false;
    }
    if source.starts_with("#!") {
        return true;
    }

    let components: Vec<&str> = path
        .components()
        .filter_map(|c| match c {
            std::path::Component::Normal(os) => os.to_str(),
            _ => None,
        })
        .collect();
    if components.is_empty()
        || components.iter().any(|&c| {
            matches!(
                c,
                "test"
                    | "tests"
                    | "__tests__"
                    | "__mocks__"
                    | "fixtures"
                    | "stories"
                    | "node_modules"
                    | "dist"
                    | "build"
            )
        })
    {
        return false;
    }

    if components[..components.len() - 1].contains(&"bin") {
        return true;
    }

    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    let parent_dir = components
        .len()
        .checked_sub(2)
        .and_then(|i| components.get(i).copied());

    match stem {
        "main" | "cli" | "server" => {
            parent_dir.is_none_or(|p| matches!(p, "src" | "app") || components.len() <= 2)
        }
        "index" | "app" => match parent_dir {
            None => true,
            Some("src") => !components
                .get(..components.len().saturating_sub(2))
                .unwrap_or_default()
                .contains(&"src"),
            Some(_) => components.len() == 2,
        },
        _ => false,
    }
}

pub(super) fn is_js_ui_kit_path(path: &Path) -> bool {
    let norm = path
        .to_string_lossy()
        .replace('\\', "/")
        .to_ascii_lowercase();
    if norm.contains("components/ui")
        || norm.contains("terminal_ui")
        || norm.contains("terminal-ui")
        || norm.contains("ascii_box")
    {
        return true;
    }
    norm.split(['/', '_', '-', '.']).any(|seg| {
        matches!(
            seg,
            "ui" | "primitives" | "theme" | "themes" | "box" | "boxes" | "ansi" | "tui"
        )
    })
}

pub(super) fn count_executable_statements_in_program(program: &Program<'_>) -> usize {
    program
        .body
        .iter()
        .map(count_executable_in_statement)
        .sum()
}

fn count_executable_in_statement(stmt: &Statement<'_>) -> usize {
    if is_zero_executable_statement(stmt) {
        return 0;
    }
    match stmt {
        Statement::BlockStatement(block) => {
            block.body.iter().map(count_executable_in_statement).sum()
        }
        Statement::FunctionDeclaration(func) => func.body.as_ref().map_or(0, |b| {
            b.statements.iter().map(count_executable_in_statement).sum()
        }),
        Statement::VariableDeclaration(var_decl) => count_executable_in_var_decl(var_decl),
        Statement::ExportDeclaration(exp) => count_executable_in_declaration(&exp.declaration),
        Statement::ExportDefaultDeclaration(exp) => count_executable_in_export_default(exp),
        Statement::IfStatement(if_stmt) => {
            1 + count_executable_in_statement(&if_stmt.consequent)
                + if_stmt
                    .alternate
                    .as_ref()
                    .map_or(0, count_executable_in_statement)
        }
        Statement::ForStatement(f) => 1 + count_executable_in_statement(&f.body),
        Statement::ForInStatement(f) => 1 + count_executable_in_statement(&f.body),
        Statement::ForOfStatement(f) => 1 + count_executable_in_statement(&f.body),
        Statement::WhileStatement(w) => 1 + count_executable_in_statement(&w.body),
        Statement::DoWhileStatement(d) => 1 + count_executable_in_statement(&d.body),
        Statement::SwitchStatement(sw) => {
            1 + sw
                .cases
                .iter()
                .flat_map(|c| &c.consequent)
                .map(count_executable_in_statement)
                .sum::<usize>()
        }
        Statement::TryStatement(tr) => count_executable_in_try(tr),
        _ => 1,
    }
}

const fn is_zero_executable_statement(stmt: &Statement<'_>) -> bool {
    matches!(
        stmt,
        Statement::ImportDeclaration(_)
            | Statement::ExportAllDeclaration(_)
            | Statement::ExportNamedDeclaration(_)
            | Statement::ExportFromDeclaration(_)
            | Statement::EmptyStatement(_)
            | Statement::TSInterfaceDeclaration(_)
            | Statement::TSTypeAliasDeclaration(_)
            | Statement::TSEnumDeclaration(_)
    )
}

fn count_executable_in_var_decl(var_decl: &oxc_ast::ast::VariableDeclaration<'_>) -> usize {
    if var_decl.declare {
        return 0;
    }
    let mut inner = 1;
    for decl in &var_decl.declarations {
        if let Some(init) = &decl.init {
            inner += count_executable_in_function_expr(init.without_parentheses());
        }
    }
    inner
}

fn count_executable_in_export_default(
    exp: &oxc_ast::ast::ExportDefaultDeclaration<'_>,
) -> usize {
    match &exp.declaration {
        oxc_ast::ast::ExportDefaultDeclarationKind::FunctionDeclaration(func) => {
            func.body.as_ref().map_or(0, |b| {
                b.statements.iter().map(count_executable_in_statement).sum()
            })
        }
        oxc_ast::ast::ExportDefaultDeclarationKind::ClassDeclaration(_)
        | oxc_ast::ast::ExportDefaultDeclarationKind::TSInterfaceDeclaration(_) => 0,
        _ => 1,
    }
}

fn count_executable_in_try(tr: &oxc_ast::ast::TryStatement<'_>) -> usize {
    let try_cnt: usize = tr
        .block
        .body
        .iter()
        .map(count_executable_in_statement)
        .sum();
    let catch_cnt: usize = tr.handler.as_ref().map_or(0, |h| {
        h.body.body.iter().map(count_executable_in_statement).sum()
    });
    let fin_cnt: usize = tr.finalizer.as_ref().map_or(0, |f| {
        f.body.iter().map(count_executable_in_statement).sum()
    });
    1 + try_cnt + catch_cnt + fin_cnt
}

fn count_executable_in_declaration(decl: &oxc_ast::ast::Declaration<'_>) -> usize {
    match decl {
        oxc_ast::ast::Declaration::FunctionDeclaration(func) => func.body.as_ref().map_or(0, |b| {
            b.statements.iter().map(count_executable_in_statement).sum()
        }),
        oxc_ast::ast::Declaration::VariableDeclaration(var_decl) => {
            count_executable_in_var_decl(var_decl)
        }
        _ => 0,
    }
}

fn count_executable_in_function_expr(expr: &Expression<'_>) -> usize {
    match expr {
        Expression::ArrowFunctionExpression(arrow) => match &arrow.body {
            oxc_ast::ast::ArrowFunctionBody::FunctionBody(b) => {
                b.statements.iter().map(count_executable_in_statement).sum()
            }
            _ => 0,
        },
        Expression::FunctionExpression(func) => func.body.as_ref().map_or(0, |b| {
            b.statements.iter().map(count_executable_in_statement).sum()
        }),
        _ => 0,
    }
}

pub(super) fn extract_static_catalog_sites(
    program: &Program<'_>,
    line_starts: &[u32],
    facets: &mut ArchitectureFileFacets,
    seen_signals: &mut BTreeSet<(ConcernBucket, u32, u32)>,
) {
    for stmt in &program.body {
        let (var_decl, outer_span) = match stmt {
            Statement::VariableDeclaration(v) => (v.as_ref(), v.span),
            Statement::ExportDeclaration(exp) => {
                if let oxc_ast::ast::Declaration::VariableDeclaration(v) = &exp.declaration {
                    (v.as_ref(), exp.span)
                } else {
                    continue;
                }
            }
            _ => continue,
        };

        for decl in &var_decl.declarations {
            let BindingPattern::BindingIdentifier(id) = &decl.id else {
                continue;
            };
            let Some(init) = &decl.init else {
                continue;
            };
            let unwrapped = unwrap_type_and_freeze_wrappers(init);
            let Some((entry_count, expr_span)) = count_static_collection_entries(unwrapped) else {
                continue;
            };
            if entry_count < MIN_CANDIDATE_CATALOG_ENTRIES {
                continue;
            }

            let site_span = if var_decl.declarations.len() == 1 {
                outer_span
            } else {
                decl.span
            };
            let byte_len = (expr_span.end.saturating_sub(expr_span.start)) as usize;
            let loc = loc_from_line_starts(line_starts, site_span.start);
            let span = ByteSpan {
                start: site_span.start,
                end: site_span.end,
            };

            facets.static_catalog_sites.push(StaticCatalogSiteIr {
                name: id.name.to_string(),
                entry_count,
                byte_len,
                loc,
                span,
            });

            if entry_count >= DEFAULT_SIGNAL_CATALOG_ENTRIES || byte_len >= 1024 {
                push_concern_signal(
                    facets,
                    seen_signals,
                    line_starts,
                    ConcernBucket::StaticDataCatalog,
                    format!("{} ({entry_count} entries)", id.name),
                    site_span,
                );
            }
        }
    }
}

fn unwrap_type_and_freeze_wrappers<'a>(expr: &'a Expression<'a>) -> &'a Expression<'a> {
    let mut curr = expr.without_parentheses();
    loop {
        match curr {
            Expression::TSAsExpression(ts_as) => {
                curr = ts_as.expression.without_parentheses();
            }
            Expression::TSSatisfiesExpression(sat) => {
                curr = sat.expression.without_parentheses();
            }
            Expression::TSTypeAssertion(assert_expr) => {
                curr = assert_expr.expression.without_parentheses();
            }
            Expression::CallExpression(call) => {
                if let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses()
                    && let Expression::Identifier(obj) = mem.object.without_parentheses()
                    && obj.name == "Object"
                    && mem.property.name == "freeze"
                    && let Some(first_arg) = call.arguments.first().and_then(|a| a.as_expression())
                {
                    curr = first_arg.without_parentheses();
                } else {
                    break;
                }
            }
            _ => break,
        }
    }
    curr
}

fn count_static_collection_entries(expr: &Expression<'_>) -> Option<(usize, Span)> {
    match expr {
        Expression::ArrayExpression(arr) => {
            let non_spread = arr
                .elements
                .iter()
                .filter(|el| !matches!(el, ArrayExpressionElement::SpreadElement(_)))
                .count();
            Some((non_spread, arr.span))
        }
        Expression::ObjectExpression(obj) => {
            let prop_count = obj
                .properties
                .iter()
                .filter(|p| {
                    matches!(p, ObjectPropertyKind::ObjectProperty(prop) if !prop.method && !matches!(
                        prop.value.without_parentheses(),
                        Expression::ArrowFunctionExpression(_) | Expression::FunctionExpression(_)
                    ))
                })
                .count();
            Some((prop_count, obj.span))
        }
        Expression::NewExpression(new_expr) => {
            if let Expression::Identifier(id) = new_expr.callee.without_parentheses()
                && matches!(id.name.as_str(), "Map" | "Set")
                && let Some(first_arg) = new_expr.arguments.first().and_then(|a| a.as_expression())
                && let Expression::ArrayExpression(arr) = unwrap_type_and_freeze_wrappers(first_arg)
            {
                return Some((arr.elements.len(), new_expr.span));
            }
            None
        }
        _ => None,
    }
}

pub(super) fn is_io_import_source(source: &str) -> bool {
    const IO_IMPORT_SOURCES: &[&str] = &[
        "fs",
        "node:fs",
        "fs/promises",
        "node:fs/promises",
        "net",
        "node:net",
        "http",
        "node:http",
        "https",
        "node:https",
        "dgram",
        "node:dgram",
        "child_process",
        "node:child_process",
        "pg",
        "mysql",
        "mysql2",
        "mysql2/promise",
        "sqlite3",
        "better-sqlite3",
        "drizzle-orm",
        "@prisma/client",
        "typeorm",
        "knex",
        "kysely",
        "mongoose",
        "mongodb",
        "redis",
        "ioredis",
        "axios",
        "undici",
        "node-fetch",
        "@supabase/supabase-js",
        "firebase/firestore",
    ];
    IO_IMPORT_SOURCES.contains(&source)
}

pub(super) fn is_entrypoint_adapter_import_source(source: &str) -> bool {
    matches!(
        source,
        "react-dom/client"
            | "@angular/platform-browser"
            | "commander"
            | "yargs"
            | "cac"
            | "minimist"
            | "node:util"
    )
}

pub(super) fn classify_io_call_expression(
    call: &CallExpression<'_>,
    semantic: &Semantic<'_>,
    call_node_id: NodeId,
) -> Option<String> {
    let _ = (semantic, call_node_id);
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => classify_direct_io_ident_call(id.name.as_str()),
        Expression::StaticMemberExpression(mem) => classify_member_io_call(mem),
        _ => None,
    }
}

fn classify_direct_io_ident_call(name: &str) -> Option<String> {
    matches!(
        name,
        "fetch"
            | "axios"
            | "readFile"
            | "readFileSync"
            | "writeFile"
            | "writeFileSync"
            | "appendFile"
            | "appendFileSync"
            | "readdir"
            | "readdirSync"
    )
    .then(|| format!("{name}(...)"))
}

fn classify_member_io_call(mem: &oxc_ast::ast::StaticMemberExpression<'_>) -> Option<String> {
    let prop = mem.property.name.as_str();
    match mem.object.without_parentheses() {
        Expression::Identifier(obj) => classify_single_receiver_io_call(obj.name.as_str(), prop),
        Expression::StaticMemberExpression(inner_mem) => {
            classify_nested_receiver_io_call(inner_mem, prop)
        }
        _ => None,
    }
}

fn classify_single_receiver_io_call(obj_name: &str, prop: &str) -> Option<String> {
    if is_single_receiver_io_method(obj_name, prop) {
        Some(format!("{obj_name}.{prop}(...)"))
    } else {
        None
    }
}

fn is_single_receiver_io_method(obj_name: &str, prop: &str) -> bool {
    match obj_name {
        "window" | "globalThis" => prop == "fetch",
        "axios" => matches!(
            prop,
            "get" | "post" | "put" | "delete" | "patch" | "request" | "head"
        ),
        "fs" | "fsPromises" => is_fs_method_name(prop),
        "db" | "pool" | "client" | "conn" | "connection" | "sql" | "knex" => matches!(
            prop,
            "query"
                | "execute"
                | "select"
                | "insert"
                | "update"
                | "delete"
                | "prepare"
                | "transaction"
                | "raw"
        ),
        "prisma" => prop.starts_with('$'),
        "supabase" => matches!(prop, "from" | "rpc"),
        "localStorage" | "sessionStorage" => {
            matches!(prop, "getItem" | "setItem" | "removeItem" | "clear")
        }
        "indexedDB" => matches!(prop, "open" | "deleteDatabase"),
        "http" | "https" => matches!(prop, "get" | "request"),
        "net" => matches!(prop, "connect" | "createConnection"),
        "Bun" => matches!(prop, "file" | "write"),
        "Deno" => prop.starts_with("read") || prop.starts_with("write"),
        _ => false,
    }
}

fn is_fs_method_name(prop: &str) -> bool {
    ["read", "write", "append", "mkdir", "rm", "unlink", "stat"]
        .iter()
        .any(|prefix| prop.starts_with(prefix))
        || matches!(prop, "existsSync" | "createReadStream" | "createWriteStream")
}

fn classify_nested_receiver_io_call(
    inner_mem: &oxc_ast::ast::StaticMemberExpression<'_>,
    prop: &str,
) -> Option<String> {
    let Expression::Identifier(root_obj) = inner_mem.object.without_parentheses() else {
        return None;
    };
    let root_name = root_obj.name.as_str();
    let mid_name = inner_mem.property.name.as_str();
    const PRISMA_MODEL_METHODS: &[&str] = &[
        "findMany",
        "findUnique",
        "findFirst",
        "findUniqueOrThrow",
        "findFirstOrThrow",
        "create",
        "createMany",
        "update",
        "updateMany",
        "upsert",
        "delete",
        "deleteMany",
        "count",
        "aggregate",
        "groupBy",
    ];
    if root_name == "prisma" && PRISMA_MODEL_METHODS.contains(&prop) {
        return Some(format!("prisma.{mid_name}.{prop}(...)"));
    }
    if root_name == "fs" && mid_name == "promises" {
        return Some(format!("fs.promises.{prop}(...)"));
    }
    None
}

pub(super) fn classify_entrypoint_adapter_call(call: &CallExpression<'_>) -> Option<String> {
    match call.callee.without_parentheses() {
        Expression::Identifier(id) => match id.name.as_str() {
            "createRoot" | "hydrateRoot" | "bootstrapApplication" | "parseArgs" => {
                Some(format!("{}(...)", id.name))
            }
            _ => None,
        },
        Expression::StaticMemberExpression(mem) => {
            if let Expression::Identifier(obj) = mem.object.without_parentheses() {
                if obj.name == "process" && mem.property.name == "exit" {
                    return Some("process.exit(...)".to_string());
                }
                if obj.name == "ReactDOM"
                    && matches!(mem.property.name.as_str(), "render" | "createRoot")
                {
                    return Some(format!("ReactDOM.{}(...)", mem.property.name));
                }
            }
            None
        }
        _ => None,
    }
}

pub(super) fn classify_dom_or_terminal_ui_call(call: &CallExpression<'_>) -> Option<String> {
    let Expression::StaticMemberExpression(mem) = call.callee.without_parentheses() else {
        return None;
    };
    let Expression::Identifier(obj) = mem.object.without_parentheses() else {
        return None;
    };
    let obj_name = obj.name.as_str();
    let prop = mem.property.name.as_str();
    if obj_name == "document" && matches!(prop, "createElement" | "createDocumentFragment") {
        return Some(format!("document.{prop}(...)"));
    }
    if matches!(obj_name, "chalk" | "kleur" | "picocolors" | "pc") {
        return Some(format!("{obj_name}.{prop}(...)"));
    }
    None
}

pub(super) fn is_root_mount_wrapper_jsx(
    semantic: &Semantic<'_>,
    jsx_node_id: NodeId,
    tag_name: &str,
) -> bool {
    if !tag_name
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_uppercase)
    {
        return false;
    }
    semantic.nodes().ancestor_ids(jsx_node_id).any(|anc_id| {
        if let AstKind::CallExpression(call) = semantic.nodes().kind(anc_id) {
            match call.callee.without_parentheses() {
                Expression::Identifier(id) => {
                    matches!(id.name.as_str(), "createRoot" | "hydrateRoot")
                }
                Expression::StaticMemberExpression(mem) => mem.property.name == "render",
                _ => false,
            }
        } else {
            false
        }
    })
}

const BOX_DRAWING_CHARS: &[char] = &[
    '┌', '─', '┐', '│', '└', '┘', '╭', '╮', '╰', '╯', '├', '┤', '┬', '┴', '┼', '═', '║', '╔', '╗',
    '╚', '╝',
];

pub(super) fn classify_terminal_ui_literal(
    cooked: &str,
    raw: &str,
) -> Option<(TerminalUiPrimitiveKind, String)> {
    let raw_lower = raw.to_ascii_lowercase();
    if cooked.contains('\x1b')
        || raw_lower.contains("\\x1b[")
        || raw_lower.contains("\\u001b[")
        || raw_lower.contains("\\u{1b}[")
        || raw_lower.contains("\\u{001b}[")
        || raw.contains("\\033[")
    {
        return Some((
            TerminalUiPrimitiveKind::AnsiEscape,
            "\\x1b[...]".to_string(),
        ));
    }
    if let Some(ch) = BOX_DRAWING_CHARS
        .iter()
        .copied()
        .find(|&c| cooked.contains(c) || raw.contains(c))
    {
        return Some((TerminalUiPrimitiveKind::BoxDrawing, ch.to_string()));
    }
    None
}

pub(super) fn is_ui_component_class(
    sym: &SymbolOutline,
    jsx_elements: &[JsxElementIr],
    source: &str,
) -> bool {
    if sym.kind != SymbolKind::Class {
        return false;
    }
    if jsx_elements
        .iter()
        .any(|jsx| spans_contain(sym.span, jsx.span))
    {
        return true;
    }
    let slice = source
        .get(sym.span.start as usize..(sym.span.end as usize).min(source.len()))
        .unwrap_or("");
    slice.contains("@Component")
        || slice.contains("@Directive")
        || slice.contains("extends Component")
        || slice.contains("extends PureComponent")
        || slice.contains("extends React.Component")
}

pub(super) fn slice_contains_inline_template(source: &str, span: Span) -> bool {
    let slice = source
        .get(span.start as usize..(span.end as usize).min(source.len()))
        .unwrap_or("");
    slice.contains("template:") && slice.contains('<')
}

pub(super) fn is_helper_or_validator_function(name: &str, source: &str, span: ByteSpan) -> bool {
    const HELPER_PREFIXES: &[&str] = &[
        "parse",
        "validate",
        "normalize",
        "compute",
        "format",
        "check",
        "is",
        "has",
        "trim",
        "extract",
        "match",
        "resolve",
        "tokenize",
        "visit",
        "build",
        "convert",
        "transform",
        "sanitize",
        "serialize",
        "deserialize",
        "encode",
        "decode",
        "make",
        "filter",
        "sort",
        "merge",
        "split",
    ];
    let lower = name.to_ascii_lowercase();
    if HELPER_PREFIXES.iter().any(|prefix| lower.starts_with(prefix)) {
        return true;
    }
    let slice = source
        .get(span.start as usize..(span.end as usize).min(source.len()))
        .unwrap_or("");
    [
        "if (",
        "switch (",
        "for (",
        "while (",
        ".split(",
        ".trim(",
        ".replace(",
        ".match(",
    ]
    .iter()
    .any(|needle| slice.contains(needle))
}
