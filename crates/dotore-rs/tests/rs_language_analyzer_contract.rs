//! Contract tests for `dotore-rs` (`RsLanguageAnalyzer` implementing `LanguageAnalyzer`).

use std::path::{Path, PathBuf};

use dotore_core::{Capability, LanguageAnalyzer, LanguageId, RuleId, SymbolKind};
use dotore_rs::{RsFileIr, RsLanguageAnalyzer};

#[test]
fn rs_language_analyzer_infers_cargo_toml_capability_gates_across_dependency_tables() {
    let analyzer = RsLanguageAnalyzer;
    assert_eq!(analyzer.language_id(), LanguageId::Rust);
    assert!(analyzer.supports_path(Path::new("src/lib.rs")));
    assert!(analyzer.supports_path(Path::new("crates/api/src/handler.rs")));
    assert!(!analyzer.supports_path(Path::new("src/App.tsx")));
    assert!(!analyzer.supports_path(Path::new("src/main.py")));
    assert!(!analyzer.supports_path(Path::new("Cargo.toml")));
    assert_eq!(analyzer.manifest_filenames(), &["Cargo.toml"]);

    let cargo_toml = r#"
[package]
name = "polyglot-backend"
version = "0.1.0"
edition = "2024"

[dependencies]
tokio = { version = "1.40", features = ["full"] }
axum = "0.8"
serde = { version = "1.0", features = ["derive"] }
custom_sql = { package = "sqlx", version = "0.8", features = ["postgres"] }

[dev-dependencies]
tracing = "0.1"

[workspace.dependencies]
leptos = "0.7"

[target.'cfg(unix)'.dependencies]
ui_core = { package = "dioxus", version = "0.6" }
"#;

    let gate = analyzer
        .infer_capability_gate(Path::new("."), &[(PathBuf::from("Cargo.toml"), cargo_toml)]);

    for expected in [
        Capability::Rust,
        Capability::Tokio,
        Capability::Axum,
        Capability::Sqlx,
        Capability::Serde,
        Capability::Tracing,
        Capability::Leptos,
        Capability::Dioxus,
    ] {
        assert!(
            gate.has(expected),
            "Expected CapabilityGate to contain {expected:?}"
        );
    }
    assert_eq!(
        gate.dependencies.get("sqlx").map(String::as_str),
        Some("0.8")
    );
    assert_eq!(
        gate.dependencies.get("dioxus").map(String::as_str),
        Some("0.6")
    );
}

#[test]
fn rs_language_analyzer_extracts_subjects_symbol_outlines_doc_comments_owners_and_suppressions() {
    let analyzer = RsLanguageAnalyzer;
    let source = r#"//! Crate module docs.

/// Max retry count for outbound requests.
pub const MAX_RETRIES: usize = 3;

/// Result alias for service calls.
pub type ServiceResult<T> = Result<T, String>;

/// Status of an order.
pub enum OrderStatus {
    Pending,
    Completed,
}

/// Repository trait for persisting orders.
pub trait OrderRepository {
    /// Loads an order by ID.
    fn find_by_id(&self, id: u64) -> Option<Order>;
}

/// Domain model representing a customer order.
pub struct Order {
    pub id: u64,
}

impl Order {
    /// Creates a new order instance.
    pub fn new(id: u64) -> Self {
        Self { id }
    }
}

/// Processes an incoming order payload.
pub fn process_order(raw: Option<Order>) -> Order {
    // dotore-disable-next-line rs-no-unwrap-in-production
    raw.unwrap()
}

pub mod internal {
    #[allow(unwrap_used)]
    pub fn allowed_unwrap(opt: Option<i32>) -> i32 {
        opt.unwrap()
    }
}
"#;

    let extracted = analyzer.extract_file(Path::new("src/order.rs"), source);
    assert_eq!(extracted.language_id, LanguageId::Rust);
    assert!(
        extracted.subjects_count >= 4,
        "Expected functions, methods, impls, and modules to be counted as subjects, got {}",
        extracted.subjects_count
    );
    assert!(!extracted.subject_spans.is_empty());
    assert!(
        !extracted
            .contextual_owner_spans
            .function_boundary_spans
            .is_empty()
    );

    let payload = extracted
        .downcast_payload::<RsFileIr>()
        .unwrap_or_else(|| panic!("Expected RsFileIr payload on ExtractedFile"));
    assert!(!payload.subjects.is_empty());

    let outlines = &extracted.symbol_outlines;
    let find_outline = |name: &str| {
        outlines
            .iter()
            .find(|o| o.name == name)
            .unwrap_or_else(|| panic!("Missing SymbolOutline for {name}; outlines: {outlines:#?}"))
    };

    let max_retries = find_outline("MAX_RETRIES");
    assert_eq!(max_retries.kind, SymbolKind::Constant);
    assert!(max_retries.exported);
    assert_eq!(
        max_retries.doc_comment.as_deref(),
        Some("Max retry count for outbound requests.")
    );

    let service_result = find_outline("ServiceResult");
    assert_eq!(service_result.kind, SymbolKind::Type);
    assert!(service_result.exported);

    let order_status = find_outline("OrderStatus");
    assert_eq!(order_status.kind, SymbolKind::Enum);
    assert!(order_status.exported);

    let order_repo = find_outline("OrderRepository");
    assert_eq!(order_repo.kind, SymbolKind::Trait);
    assert!(order_repo.exported);
    assert_eq!(
        order_repo.doc_comment.as_deref(),
        Some("Repository trait for persisting orders.")
    );

    let find_by_id = find_outline("find_by_id");
    assert_eq!(find_by_id.kind, SymbolKind::Method);
    assert_eq!(find_by_id.parent_name.as_deref(), Some("OrderRepository"));

    let order_struct = find_outline("Order");
    assert_eq!(order_struct.kind, SymbolKind::Struct);
    assert!(order_struct.exported);
    assert_eq!(
        order_struct.doc_comment.as_deref(),
        Some("Domain model representing a customer order.")
    );

    let new_method = find_outline("new");
    assert_eq!(new_method.kind, SymbolKind::Method);
    assert_eq!(new_method.parent_name.as_deref(), Some("Order"));
    assert!(new_method.exported);
    assert!(new_method.signature.contains("pub fn new(id: u64) -> Self"));

    let process_fn = find_outline("process_order");
    assert_eq!(process_fn.kind, SymbolKind::Function);
    assert!(process_fn.exported);
    assert_eq!(
        process_fn.doc_comment.as_deref(),
        Some("Processes an incoming order payload.")
    );

    // Inline suppression on `raw.unwrap()` line
    let unwrap_line = source
        .lines()
        .enumerate()
        .find_map(|(i, l)| l.contains("raw.unwrap()").then_some((i + 1) as u32))
        .unwrap_or_else(|| panic!("raw.unwrap() line"));
    assert!(
        extracted
            .suppressions
            .matches_line_or_block(RuleId::RsNoUnwrapInProduction, unwrap_line)
    );

    // Attribute suppression `#[allow(unwrap_used)]` on `allowed_unwrap`
    let attr_unwrap_line = source
        .lines()
        .enumerate()
        .find_map(|(i, l)| l.contains("opt.unwrap()").then_some((i + 1) as u32))
        .unwrap_or_else(|| panic!("opt.unwrap() line"));
    assert!(
        extracted
            .suppressions
            .matches_line_or_block(RuleId::RsNoUnwrapInProduction, attr_unwrap_line)
    );

    // Syntax validation
    assert!(analyzer.validate_syntax(Path::new("src/order.rs"), source));
    assert!(!analyzer.validate_syntax(Path::new("src/order.rs"), "pub fn broken( {"));
}

#[test]
fn rs_language_analyzer_evaluates_all_five_core_rust_safety_rules_and_skips_test_items() {
    let analyzer = RsLanguageAnalyzer;
    let cargo_toml = r#"
[package]
name = "orders-service"
version = "0.1.0"
edition = "2024"

[dependencies]
tokio = "1"
"#;
    let gate = analyzer
        .infer_capability_gate(Path::new("."), &[(PathBuf::from("Cargo.toml"), cargo_toml)]);
    let pkg = dotore_core::WorkspacePackage {
        name: "orders-service".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: gate,
        config: dotore_core::DotoreConfig::default(),
    };

    let invalid_src = r#"
pub fn bad_unwrap(input: Result<i32, String>, opt: Option<u32>) -> i32 {
    let a = input.unwrap();
    let b = opt.expect("present");
    a + (b as i32)
}

pub fn bad_slice(items: &[u64], idx: usize) -> u32 {
    let val = items[idx];
    val as u32
}

pub fn bad_unsafe_and_forget(ptr: *const u8, resource: String) -> u8 {
    std::mem::forget(resource);
    unsafe { *ptr }
}
"#;

    let extracted_invalid = analyzer.extract_file(Path::new("src/service.rs"), invalid_src);
    let result_invalid = analyzer.analyze_package(&pkg, &[extracted_invalid], None);
    let rules_triggered: Vec<RuleId> = result_invalid.diagnostics.iter().map(|d| d.rule).collect();

    for expected_rule in [
        RuleId::RsNoUnwrapInProduction,
        RuleId::RsNoUnguardedSliceIndex,
        RuleId::RsNoLossyNumericAsCast,
        RuleId::RsRequireSafetyCommentOnUnsafe,
        RuleId::RsNoMemForget,
    ] {
        assert!(
            rules_triggered.contains(&expected_rule),
            "Expected {expected_rule:?} in {rules_triggered:?}"
        );
    }

    // Adversarial valid cases: guarded slice index, try_into/from, SAFETY comment, #[cfg(test)], #[test], #[tokio::test]
    let valid_src = r#"
pub fn safe_service(items: &[u64], idx: usize, small: u8, ptr: *const u8) -> Option<u32> {
    if idx < items.len() {
        let first_checked = items[idx];
        let _ = u32::try_from(first_checked).ok()?;
    }
    if !items.is_empty() {
        let _head = items[0];
    }
    let widened = u32::from(small);
    let _lossless_as = small as u32;
    let via_get = items.get(idx).copied()?;
    let converted: u32 = via_get.try_into().ok()?;

    // SAFETY: caller guarantees `ptr` is non-null, aligned, and initialized.
    let byte = unsafe { *ptr };
    Some(widened + converted + u32::from(byte))
}

#[test]
fn unit_test_can_unwrap() {
    let v = vec![10u64];
    let x = Some(v[0]).unwrap();
    assert_eq!(x as u32, 10);
}

#[tokio::test]
async fn async_test_can_expect() {
    let v: Result<i32, &str> = Ok(42);
    assert_eq!(v.expect("ok"), 42);
}

#[cfg(test)]
mod tests {
    #[test]
    fn nested_test_items_ignored() {
        let items = [1u64, 2, 3];
        let val = Some(items[1]).unwrap();
        assert_eq!(val as u8, 2);
    }
}
"#;

    let extracted_valid = analyzer.extract_file(Path::new("src/safe_service.rs"), valid_src);
    let result_valid = analyzer.analyze_package(&pkg, &[extracted_valid], None);
    assert!(
        result_valid.diagnostics.is_empty(),
        "Expected zero diagnostics on adversarial valid Rust code, got: {:#?}",
        result_valid.diagnostics
    );
}

#[test]
fn rs_soc_rules_detect_bloated_entrypoint_mixed_io_ui_static_catalog_and_inline_terminal_primitives()
 {
    use dotore_core::{
        ConcernBucket, DotoreConfig, PrescriptionTier, RuleSeverity, WorkspacePackage,
        build_root_cause_groups_and_capsules,
    };
    use std::collections::HashMap;

    let analyzer = RsLanguageAnalyzer;
    let gate = analyzer.infer_capability_gate(
        Path::new("."),
        &[(
            PathBuf::from("Cargo.toml"),
            "[package]\nname = \"soc-demo\"\nversion = \"0.1.0\"\n[dependencies]\nsqlx = \"0.8\"\n",
        )],
    );
    let pkg = WorkspacePackage {
        name: "soc-demo".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: gate.clone(),
        config: DotoreConfig::default(),
    };

    // 1. Bloated main.rs vs thin main.rs (`arch-thin-entrypoint`)
    let bloated_main = r#"
pub struct InvoiceRecord {
    pub id: u64,
    pub amount_cents: u64,
}

pub enum InvoiceState {
    Draft,
    Paid,
}

fn compute_tax(amount: u64) -> u64 {
    let rate = 15;
    (amount * rate) / 100
}

fn main() {
    let raw = std::fs::read_to_string("invoices.txt").unwrap_or_default();
    let total = compute_tax(raw.len() as u64);
    println!("total: {total}");
}
"#;
    let extracted_bloated_main = analyzer.extract_file(Path::new("src/main.rs"), bloated_main);
    assert!(extracted_bloated_main.architecture_facets.is_entrypoint);
    assert!(
        extracted_bloated_main
            .architecture_facets
            .has_bucket(ConcernBucket::DataOrNetworkIo)
    );
    let res_main = analyzer.analyze_package(&pkg, &[extracted_bloated_main], None);
    let thin_ep_diag = res_main
        .diagnostics
        .iter()
        .find(|d| d.rule == RuleId::ArchThinEntrypoint)
        .unwrap_or_else(|| {
            panic!(
                "Expected ArchThinEntrypoint on bloated main.rs, got: {:#?}",
                res_main.diagnostics
            )
        });
    assert_eq!(thin_ep_diag.severity, RuleSeverity::Warning);
    assert_eq!(thin_ep_diag.tier, PrescriptionTier::Refactor);
    assert!(thin_ep_diag.autofix.is_none());

    let thin_main = r#"
use std::process::ExitCode;
use clap::Parser;
use soc_demo::{Cli, run_cli};

fn main() -> ExitCode {
    run_cli(Cli::parse())
}
"#;
    let extracted_thin_main = analyzer.extract_file(Path::new("src/main.rs"), thin_main);
    assert!(extracted_thin_main.architecture_facets.is_entrypoint);
    let res_thin_main = analyzer.analyze_package(&pkg, &[extracted_thin_main], None);
    assert!(
        res_thin_main.diagnostics.is_empty(),
        "Expected 0 diagnostics on thin main.rs, got: {:#?}",
        res_thin_main.diagnostics
    );

    // 2. Mixed I/O + UI presentation (`arch-no-mixed-io-and-presentation`) & inline terminal primitives (`arch-no-inline-terminal-ui-primitives`)
    let mixed_io_ui_src = r#"
pub fn sync_and_render_orders(path: &str) {
    let payload = std::fs::read_to_string(path).unwrap_or_default();
    let header = "\x1b[36;1m╭─ ORDERS SYNC ─────────╮\x1b[0m";
    let footer = "╰───────────────────────╯";
    println!("{header}\n{payload}\n{footer}");
}
"#;
    let ui_kit_src = r#"
pub struct AsciiBox {
    pub width: usize,
}
impl AsciiBox {
    pub fn render(&self) -> String {
        "\x1b[36m╭────╮\x1b[0m\n│ ok │\n╰────╯".to_string()
    }
}
"#;
    let extracted_mixed = analyzer.extract_file(Path::new("src/orders_sync.rs"), mixed_io_ui_src);
    let extracted_ui_kit = analyzer.extract_file(Path::new("src/ui.rs"), ui_kit_src);
    assert!(!extracted_mixed.architecture_facets.is_ui_kit_module);
    assert!(extracted_ui_kit.architecture_facets.is_ui_kit_module);
    assert!(
        extracted_mixed
            .architecture_facets
            .has_bucket(ConcernBucket::DataOrNetworkIo)
    );
    assert!(
        extracted_mixed
            .architecture_facets
            .has_bucket(ConcernBucket::TerminalOrUiPresentation)
    );
    assert!(
        !extracted_mixed
            .architecture_facets
            .inline_terminal_ui_sites
            .is_empty()
    );

    let res_mixed = analyzer.analyze_package(&pkg, &[extracted_mixed, extracted_ui_kit], None);
    assert!(
        res_mixed
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::ArchNoMixedIoAndPresentation
                && d.file == Path::new("src/orders_sync.rs")),
        "Expected ArchNoMixedIoAndPresentation on src/orders_sync.rs, got: {:#?}",
        res_mixed.diagnostics
    );
    let inline_ui_diag = res_mixed
        .diagnostics
        .iter()
        .find(|d| {
            d.rule == RuleId::ArchNoInlineTerminalUiPrimitives
                && d.file == Path::new("src/orders_sync.rs")
        })
        .expect("Expected ArchNoInlineTerminalUiPrimitives on src/orders_sync.rs");
    assert_eq!(inline_ui_diag.tier, PrescriptionTier::Surgical);
    assert!(inline_ui_diag.autofix.is_none());
    assert!(
        !res_mixed
            .diagnostics
            .iter()
            .any(|d| d.file == Path::new("src/ui.rs")),
        "Expected 0 diagnostics on designated UI kit module src/ui.rs, got: {:#?}",
        res_mixed.diagnostics
    );

    // 3. Static catalog mixed with >= 3 domain types (`arch-separate-static-catalog-from-types`)
    let mut entries = String::new();
    for idx in 0..26 {
        entries.push_str(&format!("    (\"R{idx:02}\", \"Rule {idx}\"),\n"));
    }
    let catalog_and_types_src = format!(
        r#"
pub struct RuleDescriptor {{
    pub id: &'static str,
    pub title: &'static str,
}}

pub enum RuleLevel {{
    Warn,
    Deny,
}}

pub struct RuleScope {{
    pub label: &'static str,
}}

pub const BUILTIN_RULE_TABLE: &[(&str, &str)] = &[
{entries}];
"#
    );
    let extracted_cat_types =
        analyzer.extract_file(Path::new("src/rules_monolith.rs"), &catalog_and_types_src);
    assert_eq!(extracted_cat_types.architecture_facets.public_type_count, 3);
    assert_eq!(
        extracted_cat_types
            .architecture_facets
            .static_catalog_sites
            .len(),
        1
    );
    assert_eq!(
        extracted_cat_types.architecture_facets.static_catalog_sites[0].entry_count,
        26
    );
    let res_cat = analyzer.analyze_package(&pkg, std::slice::from_ref(&extracted_cat_types), None);
    assert!(
        res_cat
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::ArchSeparateStaticCatalogFromTypes),
        "Expected ArchSeparateStaticCatalogFromTypes, got: {:#?}",
        res_cat.diagnostics
    );

    // Adversarial valid: catalog-only file (0 pub types) and types-only file (no >=25 catalog)
    let catalog_only_src =
        format!("pub const BUILTIN_RULE_TABLE: &[(&str, &str)] = &[\n{entries}];\n");
    let types_only_src = r#"
pub struct RuleDescriptor { pub id: &'static str }
pub enum RuleLevel { Warn, Deny }
pub struct RuleScope { pub label: &'static str }
pub const SMALL_LIST: &[&str] = &["a", "b"];
"#;
    let ext_cat_only = analyzer.extract_file(Path::new("src/catalog.rs"), &catalog_only_src);
    let ext_types_only = analyzer.extract_file(Path::new("src/types.rs"), types_only_src);
    let res_valid_split = analyzer.analyze_package(&pkg, &[ext_cat_only, ext_types_only], None);
    assert!(
        res_valid_split.diagnostics.is_empty(),
        "Expected 0 diagnostics when catalog and types are separated, got: {:#?}",
        res_valid_split.diagnostics
    );

    // Verify Fix Capsule generation for single-file SoC rules
    let mut sources = HashMap::new();
    sources.insert(
        PathBuf::from("src/rules_monolith.rs"),
        catalog_and_types_src,
    );
    let (groups, capsules) = build_root_cause_groups_and_capsules(
        std::slice::from_ref(&extracted_cat_types),
        &res_cat.diagnostics,
        &sources,
    );
    assert!(!groups.is_empty());
    assert!(!capsules.is_empty());
}

#[test]
fn rs_reuse_rules_detect_duplicated_helpers_and_repeated_struct_literals_lacking_builder() {
    use dotore_core::{
        DotoreConfig, PrescriptionTier, WorkspacePackage, build_root_cause_groups_and_capsules,
        compute_root_cause_group_id,
    };
    use std::collections::HashMap;

    let analyzer = RsLanguageAnalyzer;
    let gate = analyzer.infer_capability_gate(
        Path::new("."),
        &[(
            PathBuf::from("Cargo.toml"),
            "[package]\nname = \"reuse-demo\"\nversion = \"0.1.0\"\n",
        )],
    );
    let pkg = WorkspacePackage {
        name: "reuse-demo".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: gate,
        config: DotoreConfig::default(),
    };

    let mod_a_src = r#"
pub struct JobSpec {
    pub name: String,
    pub retries: u32,
    pub timeout_ms: Option<u64>,
    pub tags: Vec<String>,
    pub dry_run: bool,
    pub priority: u32,
}

fn normalize_slug_key(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    let lower = trimmed.to_ascii_lowercase();
    let cleaned = lower.replace(' ', "-");
    Some(cleaned)
}

pub fn build_import_job(raw: &str) -> JobSpec {
    let name = normalize_slug_key(raw).unwrap_or_default();
    JobSpec {
        name,
        retries: 0,
        timeout_ms: None,
        tags: Vec::new(),
        dry_run: false,
        priority: 0,
    }
}

pub fn build_cleanup_job() -> JobSpec {
    JobSpec {
        name: "cleanup".to_string(),
        retries: 0,
        timeout_ms: None,
        tags: Vec::new(),
        dry_run: false,
        priority: 0,
    }
}
"#;

    let mod_b_src = r#"
use crate::mod_a::JobSpec;

fn sanitize_identifier(input: &str) -> Option<String> {
    let stripped = input.trim();
    if stripped.is_empty() {
        return None;
    }
    let downcased = stripped.to_ascii_lowercase();
    let dashed = downcased.replace(' ', "-");
    Some(dashed)
}

pub fn build_export_job(label: &str) -> JobSpec {
    let name = sanitize_identifier(label).unwrap_or_default();
    JobSpec {
        name,
        retries: 0,
        timeout_ms: None,
        tags: Vec::new(),
        dry_run: false,
        priority: 0,
    }
}
"#;

    let ext_a = analyzer.extract_file(Path::new("src/mod_a.rs"), mod_a_src);
    let ext_b = analyzer.extract_file(Path::new("src/mod_b.rs"), mod_b_src);
    assert_eq!(ext_a.architecture_facets.helper_fingerprints.len(), 1);
    assert_eq!(ext_b.architecture_facets.helper_fingerprints.len(), 1);
    assert_eq!(
        ext_a.architecture_facets.helper_fingerprints[0].normalized_hash,
        ext_b.architecture_facets.helper_fingerprints[0].normalized_hash,
        "Expected renamed local variables in identical AST helpers to produce identical normalized_hash"
    );
    assert_eq!(ext_a.architecture_facets.struct_literal_sites.len(), 2);
    assert_eq!(ext_b.architecture_facets.struct_literal_sites.len(), 1);

    let extracted = vec![ext_a, ext_b];
    let res = analyzer.analyze_package(&pkg, &extracted, None);

    let dup_diags: Vec<_> = res
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::ArchNoDuplicatedHelperLogic)
        .collect();
    assert!(
        !dup_diags.is_empty(),
        "Expected ArchNoDuplicatedHelperLogic across mod_a.rs and mod_b.rs, got: {:#?}",
        res.diagnostics
    );
    assert_eq!(dup_diags[0].tier, PrescriptionTier::Refactor);
    assert!(!dup_diags[0].caller_sites.is_empty());
    if dup_diags.len() >= 2 {
        assert_eq!(
            compute_root_cause_group_id(dup_diags[0]),
            compute_root_cause_group_id(dup_diags[1])
        );
    }

    let builder_diags: Vec<_> = res
        .diagnostics
        .iter()
        .filter(|d| d.rule == RuleId::ArchPreferFluentBuilder)
        .collect();
    assert!(
        !builder_diags.is_empty(),
        "Expected ArchPreferFluentBuilder for JobSpec across 3 sites in 2 files, got: {:#?}",
        res.diagnostics
    );
    assert_eq!(builder_diags[0].tier, PrescriptionTier::Refactor);
    assert!(!builder_diags[0].caller_sites.is_empty());

    let mut sources = HashMap::new();
    sources.insert(PathBuf::from("src/mod_a.rs"), mod_a_src.to_string());
    sources.insert(PathBuf::from("src/mod_b.rs"), mod_b_src.to_string());
    let (_groups, capsules) =
        build_root_cause_groups_and_capsules(&extracted, &res.diagnostics, &sources);
    assert!(capsules.iter().any(
        |c| c.rule == RuleId::ArchNoDuplicatedHelperLogic && !c.caller_site_excerpts.is_empty()
    ));
    assert!(
        capsules.iter().any(
            |c| c.rule == RuleId::ArchPreferFluentBuilder && !c.caller_site_excerpts.is_empty()
        )
    );

    // Adversarial valid: when JobSpec defines a fluent builder / constructor, ArchPreferFluentBuilder does NOT fire
    let mod_builder_src = r#"
use crate::mod_a::JobSpec;
impl JobSpec {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            retries: 0,
            timeout_ms: None,
            tags: Vec::new(),
            dry_run: false,
            priority: 0,
        }
    }
    pub fn with_retries(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }
}
"#;
    let ext_builder = analyzer.extract_file(Path::new("src/builder.rs"), mod_builder_src);
    assert!(
        ext_builder
            .architecture_facets
            .defined_builder_types
            .contains(&"JobSpec".to_string())
    );
    let res_with_builder = analyzer.analyze_package(
        &pkg,
        &[
            analyzer.extract_file(Path::new("src/mod_a.rs"), mod_a_src),
            analyzer.extract_file(Path::new("src/mod_b.rs"), mod_b_src),
            ext_builder,
        ],
        None,
    );
    assert!(
        !res_with_builder
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::ArchPreferFluentBuilder),
        "Expected 0 ArchPreferFluentBuilder diagnostics when JobSpec has builder methods, got: {:#?}",
        res_with_builder.diagnostics
    );
}

#[test]
fn rs_architecture_monolith_thresholds_suppressions_and_workspace_self_calibration() {
    use dotore_core::{CapabilityGate, DotoreConfig, WorkspacePackage};

    let analyzer = RsLanguageAnalyzer;

    // 1. Mixed domain monolith (`arch-no-mixed-domain-monolith`) + custom thresholds
    let monolith_src = r#"
pub struct Account { pub id: u64 }
pub struct LedgerEntry { pub cents: i64 }
pub enum Currency { Usd, Eur }
pub struct AuditRecord { pub actor: String }
pub const DEFAULT_FEE_CENTS: i64 = 25;
pub const MAX_BATCH_SIZE: usize = 100;

pub async fn fetch_account(pool: &sqlx::PgPool) {
    let _ = sqlx::query!("SELECT 1").fetch_one(pool).await;
}

pub fn render_ledger_tui() {
    let _ = crossterm::execute!(std::io::stdout());
    println!("\x1b[32m┌─ LEDGER ─┐\x1b[0m");
}
"#;
    let mut custom_cfg = DotoreConfig::default();
    custom_cfg.architecture.min_monolith_domain_clusters = 3;
    custom_cfg.architecture.min_monolith_symbols = 6;
    let pkg_custom = WorkspacePackage {
        name: "monolith-demo".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_rust(),
        config: custom_cfg,
    };

    let ext_monolith = analyzer.extract_file(Path::new("src/god_module.rs"), monolith_src);
    let res_monolith = analyzer.analyze_package(&pkg_custom, &[ext_monolith], None);
    assert!(
        res_monolith
            .diagnostics
            .iter()
            .any(|d| d.rule == RuleId::ArchNoMixedDomainMonolith),
        "Expected ArchNoMixedDomainMonolith on god_module.rs, got: {:#?}",
        res_monolith.diagnostics
    );

    // 2. Inline suppressions (`// dotore-disable-next-line` and `#[allow(dotore::...)]`)
    let suppressed_src = r#"
#![allow(dotore::arch_no_mixed_io_and_presentation)]
pub fn suppressed_fn() {
    let _ = std::fs::write("out.txt", "ok");
    // dotore-disable-next-line arch-no-inline-terminal-ui-primitives
    let banner = "\x1b[31m╭─ ALERT ─╮\x1b[0m";
    println!("{banner}");
}
"#;
    let ext_suppressed = analyzer.extract_file(Path::new("src/suppressed.rs"), suppressed_src);
    let res_suppressed = analyzer.analyze_package(
        &WorkspacePackage {
            name: "suppressed-demo".to_string(),
            root_dir: PathBuf::from("."),
            capability_gate: CapabilityGate::default_rust(),
            config: DotoreConfig::default(),
        },
        &[ext_suppressed],
        None,
    );
    assert!(
        res_suppressed.diagnostics.is_empty(),
        "Expected 0 diagnostics when inline suppressions are present, got: {:#?}",
        res_suppressed.diagnostics
    );

    // 3. Self-calibration invariant across dotore's own Rust workspace files
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let arch_rules = [
        RuleId::ArchThinEntrypoint,
        RuleId::ArchNoMixedIoAndPresentation,
        RuleId::ArchSeparateStaticCatalogFromTypes,
        RuleId::ArchNoMixedDomainMonolith,
        RuleId::ArchNoInlineTerminalUiPrimitives,
        RuleId::ArchPreferFluentBuilder,
        RuleId::ArchNoDuplicatedHelperLogic,
    ];
    let real_files = [
        "src/main.rs",
        "src/cli.rs",
        "src/tui.rs",
        "src/progress.rs",
        "src/runtime_scan.rs",
        "src/runtime_scan/probe.rs",
        "src/runtime_scan/report.rs",
        "crates/dotore-core/src/ui.rs",
        "crates/dotore-core/src/search.rs",
        "crates/dotore-core/src/report/terminal.rs",
        "crates/dotore-core/src/report/why.rs",
        "crates/dotore-core/src/config/capability_gate.rs",
        "crates/dotore-core/src/rules/types.rs",
        "crates/dotore-core/src/rules/catalog/polyglot.rs",
    ];
    let mut extracted_real = Vec::new();
    for rel in real_files {
        let full = workspace_root.join(rel);
        let src = std::fs::read_to_string(&full)
            .unwrap_or_else(|e| panic!("Failed to read {}: {e}", full.display()));
        extracted_real.push(analyzer.extract_file(Path::new(rel), &src));
    }
    let pkg_self = WorkspacePackage {
        name: "dotore".to_string(),
        root_dir: PathBuf::from("."),
        capability_gate: CapabilityGate::default_rust(),
        config: DotoreConfig::default(),
    };
    let res_self = analyzer.analyze_package(&pkg_self, &extracted_real, Some(&arch_rules));
    assert!(
        res_self.diagnostics.is_empty(),
        "Expected 0 false-positive architecture diagnostics on dotore's own Rust files, got: {:#?}",
        res_self.diagnostics
    );
}
