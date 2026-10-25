//! Crate reference collector and dependency-truth evaluators (`rs-cargo-unused-dependency`
//! and `rs-cargo-test-only-dependency`) for `cargo_health`.

use std::{collections::HashSet, path::Path};

use dotore_core::{
    ByteSpan, Diagnostic, ExtractedFile, FileContext, RuleId, WorkspacePackage,
};
use proc_macro2::{TokenStream, TokenTree};
use syn::{
    Attribute, ExprPath, ItemExternCrate, ItemMod, ItemUse, Macro, UseTree,
    spanned::Spanned,
    visit::{self, Visit},
};
use toml::Value;

use crate::{
    cargo_health::{emit_manifest_diagnostic_if_active, find_toml_key_span},
    matchers::span_to_bytes,
};

type TomlMap = toml::map::Map<String, Value>;

const CAPABILITY_GATE_FIXTURE_CRATES: &[&str] = &[
    "tokio",
    "tokio-util",
    "tokio-stream",
    "axum",
    "axum-extra",
    "axum-core",
    "sqlx",
    "serde",
    "serde-json",
    "tracing",
    "leptos",
    "dioxus",
    "reqwest",
    "diesel",
    "sea-orm",
    "rusqlite",
    "postgres",
    "tokio-postgres",
    "futures",
    "tower-http",
    "actix-cors",
    "cookie",
    "jsonwebtoken",
    "crossterm",
];

/// Cross-references `[dependencies]` against crate identifiers in `files` for
/// `rs-cargo-unused-dependency` and `rs-cargo-test-only-dependency`.
#[expect(
    clippy::too_many_arguments,
    reason = "Dependency truth evaluator cross-references normal and dev tables against extracted files"
)]
pub(crate) fn inspect_dependency_truth_for_package(
    package: &WorkspacePackage,
    manifest_path: &Path,
    source: &str,
    starts: &[u32],
    pkg_name: &str,
    normal_deps: &TomlMap,
    dev_deps: Option<&TomlMap>,
    files: &[ExtractedFile],
    enabled_rules: Option<&[RuleId]>,
    out: &mut Vec<Diagnostic>,
) {
    if files.is_empty() {
        return;
    }
    for file in files {
        let Some(rs_ir) = file.downcast_payload::<crate::ir::RsFileIr>() else {
            return;
        };
        if !rs_ir.valid_syntax {
            return;
        }
    }

    let explicit_unused = enabled_rules
        .is_some_and(|l| l.contains(&RuleId::RsCargoUnusedDependency))
        || package
            .config
            .explicit_rule_override(RuleId::RsCargoUnusedDependency)
            .is_some();
    let explicit_test_only = enabled_rules
        .is_some_and(|l| l.contains(&RuleId::RsCargoTestOnlyDependency))
        || package
            .config
            .explicit_rule_override(RuleId::RsCargoTestOnlyDependency)
            .is_some();

    let all_deps_are_capability_fixture_crates = normal_deps.keys().all(|k| {
        let norm = k.trim().to_ascii_lowercase().replace('_', "-");
        CAPABILITY_GATE_FIXTURE_CRATES.contains(&norm.as_str())
    });

    let dev_dep_keys: HashSet<&str> = dev_deps
        .map(|t| t.keys().map(String::as_str).collect())
        .unwrap_or_default();

    let refs = collect_package_crate_references(files);

    for (key, val) in normal_deps {
        let is_optional = val
            .as_table()
            .and_then(|t| t.get("optional"))
            .and_then(Value::as_bool)
            == Some(true);
        if is_optional {
            continue;
        }
        let actual_pkg = val
            .as_table()
            .and_then(|t| t.get("package"))
            .and_then(Value::as_str);

        let (loc, span) = find_toml_key_span(source, starts, key);
        let key_ident = key.replace('-', "_");
        let pkg_ident = actual_pkg.map(|p| p.replace('-', "_"));

        let used_in_prod = refs.is_used_in_production(&key_ident, key)
            || pkg_ident
                .as_deref()
                .is_some_and(|pi| refs.is_used_in_production(pi, actual_pkg.unwrap_or(key)));
        let used_in_test = refs.is_used_in_tests(&key_ident, key)
            || pkg_ident
                .as_deref()
                .is_some_and(|pi| refs.is_used_in_tests(pi, actual_pkg.unwrap_or(key)));

        if !used_in_prod && !used_in_test {
            if !explicit_unused && all_deps_are_capability_fixture_crates {
                continue;
            }
            emit_manifest_diagnostic_if_active(
                package,
                manifest_path,
                source,
                RuleId::RsCargoUnusedDependency,
                key.clone(),
                "rsCargoUnusedDependency",
                format!(
                    "Declared dependency \"{key}\" is not referenced by any source file of package \"{pkg_name}\"."
                ),
                loc,
                span,
                enabled_rules,
                out,
            );
        } else if !used_in_prod && used_in_test && !dev_dep_keys.contains(key.as_str()) {
            if !explicit_test_only && all_deps_are_capability_fixture_crates {
                continue;
            }
            emit_manifest_diagnostic_if_active(
                package,
                manifest_path,
                source,
                RuleId::RsCargoTestOnlyDependency,
                key.clone(),
                "rsCargoTestOnlyDependency",
                format!(
                    "Dependency \"{key}\" is referenced only from test, bench, or `#[cfg(test)]` code; move it to `[dev-dependencies]`."
                ),
                loc,
                span,
                enabled_rules,
                out,
            );
        }
    }
}

#[derive(Default)]
struct PackageCrateReferences {
    prod_idents: HashSet<String>,
    test_idents: HashSet<String>,
    prod_sources: Vec<(String, Vec<ByteSpan>)>,
    test_sources: Vec<String>,
}

impl PackageCrateReferences {
    fn is_used_in_production(&self, underscored: &str, raw_key: &str) -> bool {
        if self.prod_idents.contains(underscored) {
            return true;
        }
        let hyphenated = raw_key.replace('_', "-");
        self.prod_sources.iter().any(|(src, test_spans)| {
            contains_crate_identifier(src, underscored, test_spans)
                || contains_crate_identifier(src, &hyphenated, test_spans)
        })
    }

    fn is_used_in_tests(&self, underscored: &str, raw_key: &str) -> bool {
        if self.test_idents.contains(underscored) {
            return true;
        }
        let hyphenated = raw_key.replace('_', "-");
        self.test_sources.iter().any(|src| {
            contains_crate_identifier(src, underscored, &[])
                || contains_crate_identifier(src, &hyphenated, &[])
        })
    }
}

fn collect_package_crate_references(files: &[ExtractedFile]) -> PackageCrateReferences {
    let mut out = PackageCrateReferences::default();
    for file in files {
        let is_test_file = file.file_context != FileContext::Production;
        let Ok(ast) = syn::parse_file(&file.source) else {
            continue;
        };
        let mut visitor = CrateRefAstVisitor {
            in_test: is_test_file || attrs_have_cfg_test(&ast.attrs),
            prod_idents: &mut out.prod_idents,
            test_idents: &mut out.test_idents,
            cfg_test_spans: Vec::new(),
        };
        visitor.visit_file(&ast);
        if is_test_file {
            out.test_sources.push(file.source.clone());
        } else {
            for sp in &visitor.cfg_test_spans {
                let start = usize::try_from(sp.start).unwrap_or(0);
                let end = usize::try_from(sp.end).unwrap_or(0);
                if let Some(sub) = file.source.get(start..end) {
                    out.test_sources.push(sub.to_string());
                }
            }
            out.prod_sources
                .push((file.source.clone(), visitor.cfg_test_spans));
        }
    }
    out
}

struct CrateRefAstVisitor<'a> {
    in_test: bool,
    prod_idents: &'a mut HashSet<String>,
    test_idents: &'a mut HashSet<String>,
    cfg_test_spans: Vec<ByteSpan>,
}

impl CrateRefAstVisitor<'_> {
    fn record_head(&mut self, raw: &str) {
        let cleaned = raw.trim_start_matches("r#");
        if cleaned.is_empty() || matches!(cleaned, "self" | "super" | "crate") {
            return;
        }
        if self.in_test {
            self.test_idents.insert(cleaned.to_string());
        } else {
            self.prod_idents.insert(cleaned.to_string());
        }
    }

    fn record_use_tree(&mut self, tree: &UseTree) {
        match tree {
            UseTree::Path(up) => self.record_head(&up.ident.to_string()),
            UseTree::Name(un) => self.record_head(&un.ident.to_string()),
            UseTree::Rename(ur) => self.record_head(&ur.ident.to_string()),
            UseTree::Group(ug) => {
                for item in &ug.items {
                    self.record_use_tree(item);
                }
            }
            UseTree::Glob(_) => {}
        }
    }

    fn record_token_stream_heads(&mut self, tokens: TokenStream) {
        let flat: Vec<TokenTree> = tokens.into_iter().collect();
        for (idx, tt) in flat.iter().enumerate() {
            if let TokenTree::Group(g) = tt {
                self.record_token_stream_heads(g.stream());
                continue;
            }
            if let TokenTree::Ident(id) = tt {
                let next_is_colon2 = matches!(
                    (flat.get(idx + 1), flat.get(idx + 2)),
                    (Some(TokenTree::Punct(p1)), Some(TokenTree::Punct(p2)))
                        if p1.as_char() == ':' && p2.as_char() == ':'
                );
                let prev_is_colon2 = idx >= 2
                    && matches!(
                        (flat.get(idx - 2), flat.get(idx - 1)),
                        (Some(TokenTree::Punct(p1)), Some(TokenTree::Punct(p2)))
                            if p1.as_char() == ':' && p2.as_char() == ':'
                    );
                if next_is_colon2 && !prev_is_colon2 {
                    self.record_head(&id.to_string());
                }
            }
        }
    }
}

impl<'ast> Visit<'ast> for CrateRefAstVisitor<'_> {
    fn visit_item_mod(&mut self, i: &'ast ItemMod) {
        let prev = self.in_test;
        if attrs_have_cfg_test(&i.attrs) || i.ident == "tests" {
            self.in_test = true;
            self.cfg_test_spans.push(span_to_bytes(i.span()));
        }
        visit::visit_item_mod(self, i);
        self.in_test = prev;
    }

    fn visit_item_fn(&mut self, i: &'ast syn::ItemFn) {
        let prev = self.in_test;
        if attrs_have_test_attr(&i.attrs) {
            self.in_test = true;
            self.cfg_test_spans.push(span_to_bytes(i.span()));
        }
        visit::visit_item_fn(self, i);
        self.in_test = prev;
    }

    fn visit_item_use(&mut self, i: &'ast ItemUse) {
        let prev = self.in_test;
        if attrs_have_cfg_test(&i.attrs) {
            self.in_test = true;
            self.cfg_test_spans.push(span_to_bytes(i.span()));
        }
        self.record_use_tree(&i.tree);
        self.in_test = prev;
    }

    fn visit_item_extern_crate(&mut self, i: &'ast ItemExternCrate) {
        self.record_head(&i.ident.to_string());
    }

    fn visit_path(&mut self, i: &'ast syn::Path) {
        if let Some(first) = i.segments.first() {
            self.record_head(&first.ident.to_string());
        }
        visit::visit_path(self, i);
    }

    fn visit_expr_path(&mut self, i: &'ast ExprPath) {
        if let Some(first) = i.path.segments.first() {
            self.record_head(&first.ident.to_string());
        }
        visit::visit_expr_path(self, i);
    }

    fn visit_macro(&mut self, i: &'ast Macro) {
        if let Some(first) = i.path.segments.first() {
            self.record_head(&first.ident.to_string());
        }
        self.record_token_stream_heads(i.tokens.clone());
        visit::visit_macro(self, i);
    }
}

fn attrs_have_cfg_test(attrs: &[Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("cfg")
            && let Ok(list) = attr.meta.require_list()
            && list.tokens.to_string().trim() == "test"
        {
            return true;
        }
    }
    false
}

fn attrs_have_test_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|attr| {
        attr.path().is_ident("test")
            || attr.path().segments.last().is_some_and(|s| s.ident == "test")
            || attrs_have_cfg_test(std::slice::from_ref(attr))
    })
}

fn contains_crate_identifier(haystack: &str, needle: &str, excluded: &[ByteSpan]) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let is_boundary = |b: Option<u8>| {
        b.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == b'_' || c == b'-'))
    };
    let mut from = 0;
    while let Some(pos) = haystack[from..].find(needle) {
        let start = from + pos;
        let end = start + needle.len();
        let in_excluded = u32::try_from(start).is_ok_and(|off| {
            excluded.iter().any(|sp| sp.start <= off && off < sp.end)
        });
        if !in_excluded
            && is_boundary(start.checked_sub(1).map(|i| bytes[i]))
            && is_boundary(bytes.get(end).copied())
        {
            return true;
        }
        from = end;
    }
    false
}
