//! Integration tests for Ticket #13 (`dotore-py` Asyncio Concurrency, Hot-Loop Performance,
//! and Cross-File Module Graph Architecture rules):
//! - `py-async-no-blocking-call`
//! - `py-async-no-sequential-await-in-loop`
//! - `py-async-no-unawaited-coroutine`
//! - `py-async-no-fire-and-forget-task`
//! - `py-perf-hoist-regex` (with `Autofix` round-trip)
//! - `py-perf-no-linear-membership-in-loop`
//! - `py-arch-no-circular-imports` (`ProjectGraph`)
//! - `py-arch-no-unused-exports` (`ProjectGraph`)

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, LanguageAnalyzer, PrescriptionTier,
    PyLanguageAnalyzer, RuleId, analyze_project_sources, analyze_source,
    analyze_source_with_config, apply_patches_to_source,
};

#[test]
fn py_async_no_blocking_call_flags_blocking_io_and_sleep_in_async_def() {
    let invalid_src = r#"import time
import requests
import subprocess
import urllib.request
from pathlib import Path

async def process_order(url: str, report_path: str) -> str:
    time.sleep(1.5)
    resp = requests.get(url, timeout=5)
    urllib.request.urlopen(url)
    subprocess.run(["ls", "-la"], check=True)
    with open(report_path, "r", encoding="utf-8") as handle:
        _ = handle.read()
    text = Path(report_path).read_text(encoding="utf-8")
    return resp.text + text
"#;

    let diags = analyze_source(
        Path::new("app/orders.py"),
        invalid_src,
        Some(&[RuleId::PyAsyncNoBlockingCall]),
    );
    assert_eq!(diags.len(), 6, "Expected 6 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PyAsyncNoBlockingCall);
        assert_eq!(diag.tier, PrescriptionTier::Surgical);
        assert_eq!(diag.subject_name.as_deref(), Some("process_order"));
    }
    assert_eq!(diags[0].loc.line, 8);
    assert_eq!(diags[1].loc.line, 9);
    assert_eq!(diags[2].loc.line, 10);
    assert_eq!(diags[3].loc.line, 11);
    assert_eq!(diags[4].loc.line, 12);
    assert_eq!(diags[5].loc.line, 14);

    // Adversarial valid cases:
    // - `await asyncio.sleep(...)`
    // - `await asyncio.to_thread(...)` and `await loop.run_in_executor(...)`
    // - `async with httpx.AsyncClient() as client: await client.get(...)`
    // - `async with aiofiles.open(...)`
    // - Synchronous `def` helper function calling `time.sleep` / `requests.get` / `open`
    let valid_src = r#"import asyncio
import time
import requests
import subprocess
from pathlib import Path

def sync_worker(url: str, path: str) -> str:
    time.sleep(0.5)
    resp = requests.post(url)
    with open(path, "r", encoding="utf-8") as f:
        _ = f.read()
    return Path(path).read_text() + resp.text

async def async_worker(url: str, path: str, client, aiofiles) -> str:
    await asyncio.sleep(0.5)
    await asyncio.to_thread(time.sleep, 1)
    resp = await asyncio.to_thread(requests.get, url)
    text = await asyncio.to_thread(Path(path).read_text)
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, subprocess.run, ["echo", "ok"])
    async with aiofiles.open(path, "r") as handle:
        data = await handle.read()
    api_resp = await client.get(url)
    return resp.text + text + data + api_resp.text
"#;
    let valid_diags = analyze_source(
        Path::new("app/safe_orders.py"),
        valid_src,
        Some(&[RuleId::PyAsyncNoBlockingCall]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on valid async code, got {valid_diags:?}"
    );

    // Works under both Capability::Python and Capability::Asyncio gates, and skips non-Python gates
    let py_gate = CapabilityGate::with_capabilities([Capability::Python]);
    assert_eq!(
        analyze_source_with_config(
            Path::new("app/orders.py"),
            invalid_src,
            &DotoreConfig::default(),
            &py_gate,
            Some(&[RuleId::PyAsyncNoBlockingCall]),
        )
        .len(),
        6
    );
    let react_gate = CapabilityGate::with_capabilities([Capability::React]);
    assert!(
        analyze_source_with_config(
            Path::new("app/orders.py"),
            invalid_src,
            &DotoreConfig::default(),
            &react_gate,
            None,
        )
        .is_empty()
    );
}

#[test]
fn py_async_no_sequential_await_in_loop_flags_independent_awaits_and_allows_gather_or_chained() {
    let invalid_src = r#"async def fetch_all_profiles(user_ids: list[str], client) -> list[dict]:
    profiles = []
    for uid in user_ids:
        data = await client.get(uid)
        profiles.append(data)
    extra = [await client.get(uid) for uid in user_ids]
    return profiles + extra
"#;

    let diags = analyze_source(
        Path::new("app/profiles.py"),
        invalid_src,
        Some(&[RuleId::PyAsyncNoSequentialAwaitInLoop]),
    );
    assert_eq!(diags.len(), 2, "Expected 2 diagnostics, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyAsyncNoSequentialAwaitInLoop);
    assert_eq!(diags[0].tier, PrescriptionTier::Surgical);
    assert_eq!(diags[0].subject_name.as_deref(), Some("fetch_all_profiles"));
    assert_eq!(diags[0].loc.line, 4);
    assert_eq!(diags[1].loc.line, 6);

    // Adversarial valid cases:
    // 1. `await asyncio.gather(...)`
    // 2. `async with asyncio.TaskGroup() as tg: for u in urls: tg.create_task(...)`
    // 3. `async for item in aiter:`
    // 4. Loop where each iteration depends on the previous iteration's awaited result (`cursor`, `token`)
    let valid_src = r#"import asyncio

async def fetch_concurrently(urls: list[str], client, stream):
    results = await asyncio.gather(*(client.get(u) for u in urls))

    async with asyncio.TaskGroup() as tg:
        for u in urls:
            tg.create_task(client.get(u))

    async for event in stream:
        await client.post(event)

    cursor = "init"
    for _ in range(5):
        page = await client.fetch_page(cursor)
        cursor = page.next_cursor

    token = "seed"
    for step in urls:
        token = await client.refresh(token, step)

    return results, cursor, token
"#;
    let valid_diags = analyze_source(
        Path::new("app/safe_profiles.py"),
        valid_src,
        Some(&[RuleId::PyAsyncNoSequentialAwaitInLoop]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on valid concurrent/chained async loops, got {valid_diags:?}"
    );
}

#[test]
fn py_async_no_unawaited_coroutine_flags_unawaited_async_calls_and_allows_scheduled_or_returned() {
    let invalid_src = r#"import asyncio

async def send_notification(user_id: str) -> None:
    await asyncio.sleep(0.1)

class InventoryService:
    async def sync_sku(self, sku: str) -> None:
        await asyncio.sleep(0.1)

    async def handle_checkout(self, user_id: str, sku: str) -> None:
        send_notification(user_id)
        self.sync_sku(sku)
        asyncio.sleep(1.0)
        forgotten = send_notification(user_id)
"#;

    let diags = analyze_source(
        Path::new("app/checkout.py"),
        invalid_src,
        Some(&[RuleId::PyAsyncNoUnawaitedCoroutine]),
    );
    assert_eq!(diags.len(), 4, "Expected 4 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PyAsyncNoUnawaitedCoroutine);
        assert_eq!(diag.tier, PrescriptionTier::Surgical);
        assert_eq!(
            diag.subject_name.as_deref(),
            Some("InventoryService.handle_checkout")
        );
    }
    assert_eq!(diags[0].loc.line, 11);
    assert_eq!(diags[1].loc.line, 12);
    assert_eq!(diags[2].loc.line, 13);
    assert_eq!(diags[3].loc.line, 14);

    let valid_src = r#"import asyncio

async def send_notification(user_id: str) -> None:
    await asyncio.sleep(0.1)

class InventoryService:
    async def sync_sku(self, sku: str) -> None:
        await asyncio.sleep(0.1)

    async def handle_checkout(self, users: list[str], sku: str):
        await send_notification(users[0])
        await self.sync_sku(sku)
        await asyncio.gather(send_notification("u1"), self.sync_sku(sku))
        async with asyncio.TaskGroup() as tg:
            tg.create_task(send_notification("u2"))
        deferred = send_notification("u3")
        await deferred
        batch = [send_notification(u) for u in users]
        await asyncio.gather(*batch)
        return send_notification("u4")
"#;
    let valid_diags = analyze_source(
        Path::new("app/safe_checkout.py"),
        valid_src,
        Some(&[RuleId::PyAsyncNoUnawaitedCoroutine]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on awaited/scheduled coroutines, got {valid_diags:?}"
    );
}

#[test]
fn py_async_no_fire_and_forget_task_flags_dangling_create_task_and_allows_strong_refs() {
    let invalid_src = r#"import asyncio

async def audit_log(event: str) -> None:
    await asyncio.sleep(0.05)

async def handle_request(event: str, loop) -> None:
    asyncio.create_task(audit_log(event))
    loop.create_task(audit_log(event))
    _ = asyncio.create_task(audit_log(event))
    dangling = asyncio.create_task(audit_log(event))
    dangling.add_done_callback(lambda _: None)
"#;

    let diags = analyze_source(
        Path::new("app/tasks.py"),
        invalid_src,
        Some(&[RuleId::PyAsyncNoFireAndForgetTask]),
    );
    assert_eq!(diags.len(), 4, "Expected 4 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PyAsyncNoFireAndForgetTask);
        assert_eq!(diag.tier, PrescriptionTier::Surgical);
        assert_eq!(diag.subject_name.as_deref(), Some("handle_request"));
    }
    assert_eq!(diags[0].loc.line, 7);
    assert_eq!(diags[1].loc.line, 8);
    assert_eq!(diags[2].loc.line, 9);
    assert_eq!(diags[3].loc.line, 10);

    let valid_src = r#"import asyncio

background_tasks: set[asyncio.Task] = set()

async def audit_log(event: str) -> None:
    await asyncio.sleep(0.05)

class Worker:
    async def schedule_safely(self, event: str):
        # 1. Stored in strong-reference set with done callback
        task = asyncio.create_task(audit_log(event))
        background_tasks.add(task)
        task.add_done_callback(background_tasks.discard)

        # 2. Awaited directly
        awaited_task = asyncio.create_task(audit_log(event))
        await awaited_task

        # 3. Passed to asyncio.gather / asyncio.wait
        gathered_task = asyncio.create_task(audit_log(event))
        await asyncio.gather(gathered_task)

        # 4. Stored on instance attribute
        self.active_task = asyncio.create_task(audit_log(event))

        # 5. Structured concurrency via TaskGroup
        async with asyncio.TaskGroup() as tg:
            tg.create_task(audit_log(event))

        # 6. Returned to caller
        return asyncio.create_task(audit_log(event))
"#;
    let valid_diags = analyze_source(
        Path::new("app/safe_tasks.py"),
        valid_src,
        Some(&[RuleId::PyAsyncNoFireAndForgetTask]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on strongly-referenced/awaited tasks, got {valid_diags:?}"
    );
}

#[test]
fn py_perf_hoist_regex_flags_compile_in_functions_and_loops_and_autofixes_to_module_scope() {
    let invalid_src = r#"import re

def validate_slug(slug: str) -> bool:
    pattern = re.compile(r"^[a-z0-9-]+$")
    return bool(pattern.match(slug))

class LogScanner:
    def count_errors(self, lines: list[str]) -> int:
        hits = 0
        for line in lines:
            if re.compile(r"\bERROR\b", re.IGNORECASE).search(line):
                hits += 1
        return hits
"#;

    let diags = analyze_source(
        Path::new("app/validators.py"),
        invalid_src,
        Some(&[RuleId::PyPerfHoistRegex]),
    );
    assert_eq!(diags.len(), 2, "Expected 2 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PyPerfHoistRegex);
        assert_eq!(diag.tier, PrescriptionTier::Autofix);
        assert!(diag.autofix.is_some());
    }
    assert_eq!(diags[0].subject_name.as_deref(), Some("validate_slug"));
    assert_eq!(diags[0].loc.line, 4);
    assert_eq!(
        diags[1].subject_name.as_deref(),
        Some("LogScanner.count_errors")
    );
    assert_eq!(diags[1].loc.line, 11);

    // Round-trip Autofix verification
    let (patched, descriptions) = apply_patches_to_source(invalid_src, &diags);
    assert_eq!(descriptions.len(), 2);
    let analyzer = PyLanguageAnalyzer::new();
    assert!(
        analyzer.validate_syntax(Path::new("app/validators.py"), &patched),
        "Patched Python source failed syntax validation:\n{patched}"
    );
    assert!(patched.contains("_COMPILED_RE = re.compile(r\"^[a-z0-9-]+$\")"));
    assert!(patched.contains("_COMPILED_RE_2 = re.compile(r\"\\bERROR\\b\", re.IGNORECASE)"));
    assert!(patched.contains("pattern = _COMPILED_RE"));
    assert!(patched.contains("if _COMPILED_RE_2.search(line):"));

    let reanalyzed = analyze_source(
        Path::new("app/validators.py"),
        &patched,
        Some(&[RuleId::PyPerfHoistRegex]),
    );
    assert!(
        reanalyzed.is_empty(),
        "Expected 0 diagnostics after Autofix, got {reanalyzed:?}\nPatched:\n{patched}"
    );

    // Adversarial valid cases: module-level re.compile and dynamic pattern strings
    let valid_src = r#"import re

_SLUG_RE = re.compile(r"^[a-z0-9-]+$")

def validate_slug(slug: str, dynamic_prefix: str) -> bool:
    dynamic_re = re.compile(f"^{dynamic_prefix}-[0-9]+$")
    return bool(_SLUG_RE.match(slug) and dynamic_re.match(slug))
"#;
    let valid_diags = analyze_source(
        Path::new("app/safe_validators.py"),
        valid_src,
        Some(&[RuleId::PyPerfHoistRegex]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics on module-level and dynamic regex compilation, got {valid_diags:?}"
    );
}

#[test]
fn py_perf_no_linear_membership_in_loop_flags_list_in_loop_and_allows_sets() {
    let invalid_src = r#"def filter_active_events(events: list[dict], raw_blocked: set[str]) -> list[dict]:
    allowed_kinds = ["click", "view", "purchase", "signup"]
    blocked_ids = list(raw_blocked)
    computed_tags = [e["tag"] for e in events]
    out = []
    for ev in events:
        if ev["kind"] in ["click", "view", "purchase"]:
            out.append(ev)
        if ev["kind"] in allowed_kinds:
            out.append(ev)
        if ev["id"] not in blocked_ids:
            out.append(ev)
    matched = [ev for ev in events if ev["tag"] in computed_tags]
    return out + matched
"#;

    let diags = analyze_source(
        Path::new("app/events.py"),
        invalid_src,
        Some(&[RuleId::PyPerfNoLinearMembershipInLoop]),
    );
    assert_eq!(diags.len(), 4, "Expected 4 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PyPerfNoLinearMembershipInLoop);
        assert_eq!(diag.tier, PrescriptionTier::Surgical);
        assert_eq!(diag.subject_name.as_deref(), Some("filter_active_events"));
    }
    assert_eq!(diags[0].loc.line, 7);
    assert_eq!(diags[1].loc.line, 9);
    assert_eq!(diags[2].loc.line, 11);
    assert_eq!(diags[3].loc.line, 13);

    let valid_src = r#"def filter_active_events_fast(events: list[dict], raw_blocked: list[str], single_kind: str) -> list[dict]:
    allowed_kinds = {"click", "view", "purchase", "signup"}
    blocked_ids = set(raw_blocked)
    computed_tags = {e["tag"] for e in events}
    local_list = ["a", "b", "c"]

    # Membership check outside a loop is fine
    if single_kind in local_list:
        pass

    out = []
    for ev in events:
        if ev["kind"] in {"click", "view", "purchase"}:
            out.append(ev)
        if ev["kind"] in allowed_kinds:
            out.append(ev)
        if ev["id"] not in blocked_ids:
            out.append(ev)
    matched = [ev for ev in events if ev["tag"] in computed_tags]
    return out + matched
"#;
    let valid_diags = analyze_source(
        Path::new("app/safe_events.py"),
        valid_src,
        Some(&[RuleId::PyPerfNoLinearMembershipInLoop]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics when using sets for loop membership, got {valid_diags:?}"
    );
}

#[test]
fn py_arch_no_circular_imports_flags_module_cycles_and_ignores_type_checking_blocks() {
    let orders_py = r#"from app.payments import charge_card

def create_order(amount: int) -> str:
    return charge_card(amount)
"#;
    let payments_py = r#"from .orders import create_order

def charge_card(amount: int) -> str:
    return f"charged:{amount}"
"#;

    let report = analyze_project_sources(
        vec![
            (PathBuf::from("app/orders.py"), orders_py.to_string()),
            (PathBuf::from("app/payments.py"), payments_py.to_string()),
        ],
        Some(&[RuleId::PyArchNoCircularImports]),
    );
    assert!(
        !report.diagnostics.is_empty(),
        "Expected circular import diagnostics, got none"
    );
    for diag in &report.diagnostics {
        assert_eq!(diag.rule, RuleId::PyArchNoCircularImports);
        assert_eq!(diag.tier, PrescriptionTier::Refactor);
        assert!(
            diag.message.contains("orders.py") && diag.message.contains("payments.py"),
            "Expected cycle message to mention both modules, got: {}",
            diag.message
        );
    }

    // Adversarial valid case: cycle broken by `if TYPE_CHECKING:` guard
    let safe_orders_py = r#"from app.payments import charge_card

class Order:
    pass

def create_order(amount: int) -> str:
    return charge_card(amount)
"#;
    let safe_payments_py = r#"from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.orders import Order

def charge_card(amount: int) -> str:
    return f"charged:{amount}"
"#;

    let safe_report = analyze_project_sources(
        vec![
            (PathBuf::from("app/orders.py"), safe_orders_py.to_string()),
            (
                PathBuf::from("app/payments.py"),
                safe_payments_py.to_string(),
            ),
        ],
        Some(&[RuleId::PyArchNoCircularImports]),
    );
    assert!(
        safe_report.diagnostics.is_empty(),
        "Expected 0 circular import diagnostics when guarded by TYPE_CHECKING, got {:?}",
        safe_report.diagnostics
    );
}

#[test]
fn py_arch_no_unused_exports_flags_dead_public_symbols_and_respects_entrypoints_decorators_and_dunder_all()
 {
    let main_py = r#"from app.utils import format_currency, CurrencyConfig, DEFAULT_CURRENCY

def run_app() -> str:
    cfg = CurrencyConfig()
    return format_currency(100, DEFAULT_CURRENCY, cfg)
"#;
    let utils_py = r#"__all__ = ["explicitly_exported_fn"]

DEFAULT_CURRENCY = "USD"
UNUSED_TAX_RATE = 0.08

class CurrencyConfig:
    pass

class UnusedAuditFormatter:
    pass

def format_currency(cents: int, code: str, cfg: CurrencyConfig) -> str:
    return _format_impl(cents, code)

def _format_impl(cents: int, code: str) -> str:
    return f"{code} {cents / 100:.2f}"

def unused_calculate_discount(cents: int) -> int:
    return cents

def explicitly_exported_fn() -> str:
    return "ok"

@router.get("/health")
def health_endpoint() -> dict:
    return {"ok": True}
"#;

    let report = analyze_project_sources(
        vec![
            (PathBuf::from("app/main.py"), main_py.to_string()),
            (PathBuf::from("app/utils.py"), utils_py.to_string()),
        ],
        Some(&[RuleId::PyArchNoUnusedExports]),
    );
    let mut targets: Vec<&str> = report
        .diagnostics
        .iter()
        .map(|d| d.target_name.as_str())
        .collect();
    targets.sort_unstable();
    assert_eq!(
        targets,
        vec![
            "UNUSED_TAX_RATE",
            "UnusedAuditFormatter",
            "unused_calculate_discount"
        ],
        "Unexpected unused export diagnostics: {:?}",
        report.diagnostics
    );
    for diag in &report.diagnostics {
        assert_eq!(diag.rule, RuleId::PyArchNoUnusedExports);
        assert_eq!(diag.tier, PrescriptionTier::Surgical);
        assert_eq!(diag.file, PathBuf::from("app/utils.py"));
    }
}

#[test]
fn cross_file_unawaited_coroutine_and_all_8_rules_catalog_and_fix_capsules() {
    let mailer_py = r#"import asyncio

async def send_welcome_email(email: str) -> None:
    await asyncio.sleep(0.1)
"#;
    let signup_py = r#"from app.mailer import send_welcome_email

async def register_user(email: str) -> dict:
    send_welcome_email(email)
    await send_welcome_email(email)
    return {"email": email}
"#;

    let report = analyze_project_sources(
        vec![
            (PathBuf::from("app/mailer.py"), mailer_py.to_string()),
            (PathBuf::from("app/signup.py"), signup_py.to_string()),
        ],
        Some(&[RuleId::PyAsyncNoUnawaitedCoroutine]),
    );
    assert_eq!(
        report.diagnostics.len(),
        1,
        "Expected 1 cross-file unawaited coroutine diagnostic, got {:?}",
        report.diagnostics
    );
    assert_eq!(
        report.diagnostics[0].rule,
        RuleId::PyAsyncNoUnawaitedCoroutine
    );
    assert_eq!(report.diagnostics[0].file, PathBuf::from("app/signup.py"));
    assert_eq!(
        report.diagnostics[0].subject_name.as_deref(),
        Some("register_user")
    );
    assert_eq!(report.diagnostics[0].loc.line, 4);
    assert!(!report.fix_capsules.is_empty());

    let expected_ids = [
        ("py-async-no-blocking-call", RuleId::PyAsyncNoBlockingCall),
        (
            "py-async-no-sequential-await-in-loop",
            RuleId::PyAsyncNoSequentialAwaitInLoop,
        ),
        (
            "py-async-no-unawaited-coroutine",
            RuleId::PyAsyncNoUnawaitedCoroutine,
        ),
        (
            "py-async-no-fire-and-forget-task",
            RuleId::PyAsyncNoFireAndForgetTask,
        ),
        ("py-perf-hoist-regex", RuleId::PyPerfHoistRegex),
        (
            "py-perf-no-linear-membership-in-loop",
            RuleId::PyPerfNoLinearMembershipInLoop,
        ),
        (
            "py-arch-no-circular-imports",
            RuleId::PyArchNoCircularImports,
        ),
        ("py-arch-no-unused-exports", RuleId::PyArchNoUnusedExports),
    ];
    let cfg = DotoreConfig::default();
    for (canonical_id, rule_id) in expected_ids {
        assert_eq!(RuleId::parse(canonical_id), Some(rule_id));
        assert_eq!(rule_id.as_str(), canonical_id);
        let explained = dotore::explain_rule(canonical_id, &cfg)
            .unwrap_or_else(|| panic!("Missing explain_rule entry for {canonical_id}"));
        assert_eq!(explained.id, canonical_id);
        assert_eq!(explained.framework, "python");
    }
}
