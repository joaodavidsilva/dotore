//! Integration tests for Ticket #54 (`dotore-py` Python Zen, Complexity, Wildcard Imports,
//! and Exception Fallback-Chain Calibration):
//! - `py-zen-complex-function`
//! - `py-zen-deep-nesting`
//! - `py-zen-long-function`
//! - `py-zen-too-many-params`
//! - `py-zen-large-class`
//! - `py-zen-no-dense-semicolon-statements`
//! - `py-no-wildcard-import`
//! - `py-no-silent-broad-except` (loop `continue` + consecutive `try` fallback-chain exemption)

use std::{fmt::Write as _, path::{Path, PathBuf}};

use dotore::{
    PrescriptionTier, PyLanguageAnalyzer, LanguageAnalyzer, RuleId, analyze_project_sources,
    analyze_source, apply_patches_to_source,
};

#[test]
fn py_zen_complex_function_flags_high_cyclomatic_and_cognitive_complexity() {
    let invalid_src = r#"def evaluate_order_rules(order, user, flags, items):
    score = 0
    if order.is_urgent and user.is_vip or flags.force_priority:
        score += 10
    elif order.total > 1000 and not order.is_flagged:
        score += 5
    elif order.total > 500:
        score += 3
    for item in items:
        if item.in_stock and item.price > 0:
            score += 1
        elif item.backordered:
            score -= 1
    while score > 100:
        score -= 10
    with order.lock(), user.session():
        try:
            assert score >= 0
            bonus = 2 if user.is_active else 0
            valid_ids = [x.id for x in items if x.valid if not x.archived]
            score += bonus + len(valid_ids)
        except ValueError:
            score = 0
        except KeyError:
            score = -1
    return score
"#;

    let diags = analyze_source(
        Path::new("app/orders.py"),
        invalid_src,
        Some(&[RuleId::PyZenComplexFunction]),
    );
    assert_eq!(diags.len(), 1, "Expected 1 diagnostic, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyZenComplexFunction);
    assert_eq!(diags[0].tier, PrescriptionTier::Refactor);
    assert_eq!(diags[0].subject_name.as_deref(), Some("evaluate_order_rules"));
    assert_eq!(diags[0].target_name, "evaluate_order_rules");
    assert_eq!(diags[0].loc.line, 1);
    assert!(
        diags[0].message.contains("complexity"),
        "Expected complexity details in message, got: {}",
        diags[0].message
    );

    // Valid case: simple function + outer function whose nested helper has branches
    // (nested def branches must not be charged to outer function).
    let valid_src = r#"def simple_branching(a: int, b: int, c: int) -> int:
    if a > 0 and b > 0:
        return a + b
    elif c > 0:
        return c
    return 0

def outer_orchestrator(x: int) -> int:
    if x <= 0:
        return 0
    def inner_helper(y: int) -> int:
        if y == 1:
            return 1
        elif y == 2:
            return 2
        elif y == 3:
            return 3
        elif y == 4:
            return 4
        return 0
    return inner_helper(x)
"#;
    let valid_diags = analyze_source(
        Path::new("app/simple.py"),
        valid_src,
        Some(&[RuleId::PyZenComplexFunction]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on simple/nested functions, got {valid_diags:?}"
    );
}

#[test]
fn py_zen_deep_nesting_flags_control_flow_depth_above_five_and_allows_flat_elif() {
    let invalid_src = r#"class Processor:
    def deeply_nested_process(self, batches):
        if batches:
            for batch in batches:
                while batch.has_next():
                    with batch.acquire_context():
                        try:
                            if batch.is_valid():
                                return batch.consume()
                        except RuntimeError:
                            pass
        return None
"#;

    let diags = analyze_source(
        Path::new("app/processor.py"),
        invalid_src,
        Some(&[RuleId::PyZenDeepNesting]),
    );
    assert_eq!(diags.len(), 1, "Expected 1 diagnostic, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyZenDeepNesting);
    assert_eq!(diags[0].tier, PrescriptionTier::Surgical);
    assert_eq!(
        diags[0].subject_name.as_deref(),
        Some("Processor.deeply_nested_process")
    );
    assert_eq!(diags[0].target_name, "deeply_nested_process");
    assert_eq!(diags[0].loc.line, 2);
    assert!(diags[0].message.contains("6"));

    // Valid cases: depth == 5, and long flat if/elif/elif chains (depth == 1)
    let valid_src = r#"def depth_five_ok(batches):
    if batches:
        for batch in batches:
            while batch.has_next():
                with batch.acquire_context():
                    if batch.is_valid():
                        return batch.consume()
    return None

def flat_elif_chain(code: int) -> str:
    if code == 1:
        return "one"
    elif code == 2:
        return "two"
    elif code == 3:
        return "three"
    elif code == 4:
        return "four"
    elif code == 5:
        return "five"
    elif code == 6:
        return "six"
    elif code == 7:
        return "seven"
    else:
        return "other"
"#;
    assert!(
        analyze_source(
            Path::new("app/flat.py"),
            valid_src,
            Some(&[RuleId::PyZenDeepNesting]),
        )
        .is_empty()
    );
}

#[test]
fn py_zen_long_function_flags_bodies_over_75_lines() {
    let mut invalid_src = String::from("def oversized_pipeline(data: list[int]) -> int:\n    total = 0\n");
    for i in 1..=75 {
        let _ = writeln!(invalid_src, "    total += {i}");
    }
    invalid_src.push_str("    return total\n");

    let diags = analyze_source(
        Path::new("app/pipeline.py"),
        &invalid_src,
        Some(&[RuleId::PyZenLongFunction]),
    );
    assert_eq!(diags.len(), 1, "Expected 1 diagnostic, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyZenLongFunction);
    assert_eq!(diags[0].tier, PrescriptionTier::Refactor);
    assert_eq!(diags[0].subject_name.as_deref(), Some("oversized_pipeline"));
    assert_eq!(diags[0].target_name, "oversized_pipeline");
    assert_eq!(diags[0].loc.line, 1);
    assert!(diags[0].message.contains("77"));

    // Valid case: body spanning 75 lines or fewer
    let mut valid_src = String::from("def concise_pipeline(data: list[int]) -> int:\n");
    for i in 1..=74 {
        let _ = writeln!(valid_src, "    total_{i} = {i}");
    }
    valid_src.push_str("    return total_1\n");
    assert!(
        analyze_source(
            Path::new("app/concise.py"),
            &valid_src,
            Some(&[RuleId::PyZenLongFunction]),
        )
        .is_empty()
    );
}

#[test]
fn py_zen_too_many_params_flags_over_10_params_excluding_self_cls_and_init() {
    let invalid_src = r#"def configure_deployment(
    env,
    region,
    cluster,
    namespace,
    image,
    tag,
    replicas,
    cpu_limit,
    memory_limit,
    timeout_sec,
    dry_run=False,
):
    return env

class ReportBuilder:
    def build_report(
        self,
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        *args,
        **kwargs,
    ):
        return p1
"#;

    let diags = analyze_source(
        Path::new("app/deploy.py"),
        invalid_src,
        Some(&[RuleId::PyZenTooManyParams]),
    );
    assert_eq!(diags.len(), 2, "Expected 2 diagnostics, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyZenTooManyParams);
    assert_eq!(diags[0].subject_name.as_deref(), Some("configure_deployment"));
    assert_eq!(diags[0].target_name, "configure_deployment");
    assert!(diags[0].message.contains("11"));

    assert_eq!(
        diags[1].subject_name.as_deref(),
        Some("ReportBuilder.build_report")
    );
    assert_eq!(diags[1].target_name, "build_report");
    assert!(diags[1].message.contains("11"));

    // Valid cases:
    // - Method with `self` + 10 parameters (total 11, excluding `self` = 10)
    // - Classmethod with `cls` + 10 parameters (excluding `cls` = 10)
    // - `__init__` and `__init_subclass__` with > 10 parameters (skipped)
    let valid_src = r#"class ServiceClient:
    def __init__(self, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12):
        self.a1 = a1

    def __init_subclass__(cls, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, **kwargs):
        super().__init_subclass__(**kwargs)

    def ten_params_with_self(self, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10):
        return p1

    @classmethod
    def ten_params_with_cls(cls, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10):
        return p1
"#;
    assert!(
        analyze_source(
            Path::new("app/client.py"),
            valid_src,
            Some(&[RuleId::PyZenTooManyParams]),
        )
        .is_empty()
    );
}

#[test]
fn py_zen_large_class_flags_classes_with_over_20_methods() {
    let mut invalid_src = String::from("class GodController:\n");
    for i in 1..=21 {
        let _ = writeln!(invalid_src, "    def action_{i}(self) -> int:\n        return {i}\n");
    }

    let diags = analyze_source(
        Path::new("app/controller.py"),
        &invalid_src,
        Some(&[RuleId::PyZenLargeClass]),
    );
    assert_eq!(diags.len(), 1, "Expected 1 diagnostic, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyZenLargeClass);
    assert_eq!(diags[0].tier, PrescriptionTier::Refactor);
    assert_eq!(diags[0].subject_name.as_deref(), Some("GodController"));
    assert_eq!(diags[0].target_name, "GodController");
    assert_eq!(diags[0].loc.line, 1);
    assert!(diags[0].message.contains("21"));

    // Valid case: class with exactly 20 methods
    let mut valid_src = String::from("class FocusedController:\n");
    for i in 1..=20 {
        let _ = writeln!(valid_src, "    def action_{i}(self) -> int:\n        return {i}\n");
    }
    assert!(
        analyze_source(
            Path::new("app/focused.py"),
            &valid_src,
            Some(&[RuleId::PyZenLargeClass]),
        )
        .is_empty()
    );
}

#[test]
fn py_zen_no_dense_semicolon_statements_flags_chained_statements_and_ignores_strings_and_comments() {
    let invalid_src = r#"def compute_totals(x: int) -> int:
    a = x + 1; b = a * 2; c = b - 3
    return c
"#;

    let diags = analyze_source(
        Path::new("app/dense.py"),
        invalid_src,
        Some(&[RuleId::PyZenNoDenseSemicolonStatements]),
    );
    assert_eq!(diags.len(), 1, "Expected 1 diagnostic, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyZenNoDenseSemicolonStatements);
    assert_eq!(diags[0].tier, PrescriptionTier::Autofix);
    assert_eq!(diags[0].subject_name.as_deref(), Some("compute_totals"));
    assert_eq!(diags[0].loc.line, 2);

    // Autofix round-trip verification
    let (patched, descriptions) = apply_patches_to_source(invalid_src, &diags);
    assert_eq!(descriptions.len(), 1);
    let analyzer = PyLanguageAnalyzer::new();
    assert!(
        analyzer.validate_syntax(Path::new("app/dense.py"), &patched),
        "Patched Python source failed syntax validation:\n{patched}"
    );
    assert!(
        analyze_source(
            Path::new("app/dense.py"),
            &patched,
            Some(&[RuleId::PyZenNoDenseSemicolonStatements]),
        )
        .is_empty()
    );

    // Valid cases: semicolons in strings, comments, multiline strings, or single statement
    let valid_src = r#"# Header comment with ; ; ; semicolons
 SQL_QUERY = "SELECT 1; SELECT 2; SELECT 3;"
DOC = """
a = 1; b = 2; c = 3
"""

def format_header() -> str:
    prefix = "a;b;c"  # inline comment with ; semicolon
    return f"{prefix};done;"
"#;
    assert!(
        analyze_source(
            Path::new("app/clean_strings.py"),
            valid_src,
            Some(&[RuleId::PyZenNoDenseSemicolonStatements]),
        )
        .is_empty()
    );
}

#[test]
fn py_no_wildcard_import_flags_star_imports_outside_init_py() {
    let invalid_src = r#"from math import *
from .helpers import *

def calc(x: float) -> float:
    return sin(x)
"#;

    let diags = analyze_source(
        Path::new("app/calc.py"),
        invalid_src,
        Some(&[RuleId::PyNoWildcardImport]),
    );
    assert_eq!(diags.len(), 2, "Expected 2 diagnostics, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyNoWildcardImport);
    assert_eq!(diags[0].tier, PrescriptionTier::Surgical);
    assert_eq!(diags[0].loc.line, 1);
    assert!(diags[0].message.contains("from math import *"));
    assert_eq!(diags[1].loc.line, 2);
    assert!(diags[1].message.contains("from .helpers import *"));

    // Allowed in `__init__.py` for public package re-exports and in `.pyi` stub files
    assert!(
        analyze_source(
            Path::new("app/__init__.py"),
            invalid_src,
            Some(&[RuleId::PyNoWildcardImport]),
        )
        .is_empty()
    );
    assert!(
        analyze_source(
            Path::new("app/calc.pyi"),
            invalid_src,
            Some(&[RuleId::PyNoWildcardImport]),
        )
        .is_empty()
    );

    // Explicit named imports are valid
    let valid_src = "from math import sin, cos\nimport os\n";
    assert!(
        analyze_source(
            Path::new("app/calc.py"),
            valid_src,
            Some(&[RuleId::PyNoWildcardImport]),
        )
        .is_empty()
    );
}

#[test]
fn py_no_silent_broad_except_flags_loop_continue_and_exempts_consecutive_try_fallback_chains() {
    // 1. Standalone `except Exception: continue` and `except BaseException: continue` in loops must fire
    let loop_invalid_src = r#"def ingest_rows(rows):
    valid = []
    for row in rows:
        try:
            valid.append(parse_row(row))
        except Exception:
            continue

    while rows:
        try:
            process_item(rows.pop())
        except BaseException:
            continue
    return valid
"#;

    let diags = analyze_source(
        Path::new("app/ingest.py"),
        loop_invalid_src,
        Some(&[RuleId::PyNoSilentBroadExcept]),
    );
    assert_eq!(diags.len(), 2, "Expected 2 diagnostics, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyNoSilentBroadExcept);
    assert_eq!(diags[0].subject_name.as_deref(), Some("ingest_rows"));
    assert_eq!(diags[0].loc.line, 6);
    assert_eq!(diags[1].loc.line, 12);

    // 2. Consecutive `try ... except ...: pass/continue` fallback chains (>= 2 in same block) must emit 0 diagnostics
    let fallback_valid_src = r#"def decode_payload(raw: bytes) -> str:
    result = None
    try:
        result = raw.decode("utf-8")
    except Exception:
        pass
    try:
        if result is None:
            result = raw.decode("latin-1")
    except Exception:
        pass
    return result or ""

def try_providers_in_loop(items):
    for item in items:
        try:
            if try_primary(item):
                continue
        except Exception:
            pass
        try:
            if try_secondary(item):
                continue
        except Exception:
            continue
"#;

    let fallback_diags = analyze_source(
        Path::new("app/fallback.py"),
        fallback_valid_src,
        Some(&[RuleId::PyNoSilentBroadExcept]),
    );
    assert!(
        fallback_diags.is_empty(),
        "Expected 0 diagnostics on consecutive try fallback chains, got {fallback_diags:?}"
    );
}

#[test]
fn zen_and_wildcard_rules_skip_test_and_example_files_by_default_and_work_in_project_analysis() {
    let noisy_src = r#"from math import *

def dense_and_many_params(p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11):
    a = 1; b = 2; c = 3
    if p1:
        for x in p2:
            while x:
                with p3():
                    try:
                        if p4:
                            return a + b + c
                    except ValueError:
                        return 0
    return a
"#;

    // Test and example files are skipped when `enabled_rules` is `None` (default scan)
    for non_prod_path in [
        "tests/test_helpers.py",
        "app/test_module.py",
        "examples/demo_script.py",
        "benchmarks/bench_math.py",
    ] {
        let diags = analyze_source(Path::new(non_prod_path), noisy_src, None);
        let zen_or_wildcard: Vec<RuleId> = diags
            .iter()
            .map(|d| d.rule)
            .filter(|r| {
                matches!(
                    r,
                    RuleId::PyZenComplexFunction
                        | RuleId::PyZenDeepNesting
                        | RuleId::PyZenLongFunction
                        | RuleId::PyZenTooManyParams
                        | RuleId::PyZenLargeClass
                        | RuleId::PyZenNoDenseSemicolonStatements
                        | RuleId::PyNoWildcardImport
                )
            })
            .collect();
        assert!(
            zen_or_wildcard.is_empty(),
            "Expected test/example file {non_prod_path} to skip test-noise Zen/wildcard rules by default, got {zen_or_wildcard:?}"
        );
    }

    // End-to-end `analyze_project_sources` verification on production files vs test files
    let report = analyze_project_sources(
        vec![
            (
                PathBuf::from("pyproject.toml"),
                r#"[project]
name = "zen-service"
version = "0.1.0"
"#
                .to_string(),
            ),
            (PathBuf::from("src/service.py"), noisy_src.to_string()),
            (PathBuf::from("tests/test_service.py"), noisy_src.to_string()),
        ],
        None,
    );

    let service_rules: Vec<RuleId> = report
        .diagnostics
        .iter()
        .filter(|d| d.file == Path::new("src/service.py"))
        .map(|d| d.rule)
        .collect();
    assert!(service_rules.contains(&RuleId::PyNoWildcardImport));
    assert!(service_rules.contains(&RuleId::PyZenTooManyParams));
    assert!(service_rules.contains(&RuleId::PyZenDeepNesting));
    assert!(service_rules.contains(&RuleId::PyZenNoDenseSemicolonStatements));

    let test_diags: Vec<_> = report
        .diagnostics
        .iter()
        .filter(|d| d.file == Path::new("tests/test_service.py"))
        .collect();
    assert!(
        test_diags.is_empty(),
        "Expected 0 diagnostics on tests/test_service.py, got {test_diags:?}"
    );
}
