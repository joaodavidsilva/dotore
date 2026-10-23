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

    let gate = analyzer.infer_capability_gate(
        Path::new("."),
        &[(PathBuf::from("Cargo.toml"), cargo_toml)],
    );

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
    assert!(extracted.suppressions.matches_line_or_block(
        RuleId::RsNoUnwrapInProduction,
        unwrap_line
    ));

    // Attribute suppression `#[allow(unwrap_used)]` on `allowed_unwrap`
    let attr_unwrap_line = source
        .lines()
        .enumerate()
        .find_map(|(i, l)| l.contains("opt.unwrap()").then_some((i + 1) as u32))
        .unwrap_or_else(|| panic!("opt.unwrap() line"));
    assert!(extracted.suppressions.matches_line_or_block(
        RuleId::RsNoUnwrapInProduction,
        attr_unwrap_line
    ));

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
    let gate = analyzer.infer_capability_gate(
        Path::new("."),
        &[(PathBuf::from("Cargo.toml"), cargo_toml)],
    );
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
    let rules_triggered: Vec<RuleId> = result_invalid
        .diagnostics
        .iter()
        .map(|d| d.rule)
        .collect();

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
