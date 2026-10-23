//! Integration tests for Ticket #14 (`dotore-py` web, ORM, and security rules):
//! - `py-pydantic-prefer-default-factory` (`Capability::Pydantic`, `Autofix`)
//! - `py-fastapi-require-response-model` (`Capability::FastApi`)
//! - `py-fastapi-mutating-route-requires-auth` (`Capability::FastApi`)
//! - `py-orm-no-query-in-loop` (`Capability::SqlAlchemy` / `Capability::Django`)
//! - `py-security-no-raw-sql-interpolation` (`Capability::Python`)
//! - `py-security-no-unsafe-deserialization-or-shell` (`Capability::Python`, `Autofix`)

use std::path::{Path, PathBuf};

use dotore::{
    Capability, CapabilityGate, DotoreConfig, LanguageAnalyzer, PrescriptionTier,
    PyLanguageAnalyzer, RuleId, analyze_project_sources, analyze_source,
    analyze_source_with_config, apply_patches_to_source,
};

#[test]
fn py_pydantic_prefer_default_factory_flags_mutable_and_runtime_defaults_and_autofixes() {
    let invalid_src = r#"from datetime import datetime, timezone
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

class UserCreate(BaseModel):
    tags: list[str] = Field(default=[])
    metadata: dict[str, str] = Field(default={}, description="meta")
    roles: set[str] = Field(default=set())
    created_at: datetime = Field(default=datetime.now(timezone.utc))
    request_id: UUID = Field(default=uuid4())
    bare_items: list[int] = []
"#;

    let diags = analyze_source(
        Path::new("app/schemas.py"),
        invalid_src,
        Some(&[RuleId::PyPydanticPreferDefaultFactory]),
    );
    assert_eq!(diags.len(), 6, "Expected 6 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PyPydanticPreferDefaultFactory);
        assert_eq!(diag.tier, PrescriptionTier::Autofix);
        assert!(diag.autofix.is_some());
    }
    assert_eq!(diags[0].loc.line, 6);
    assert_eq!(diags[1].loc.line, 7);
    assert_eq!(diags[2].loc.line, 8);
    assert_eq!(diags[3].loc.line, 9);
    assert_eq!(diags[4].loc.line, 10);
    assert_eq!(diags[5].loc.line, 11);

    // Round-trip Autofix verification
    let (patched, descriptions) = apply_patches_to_source(invalid_src, &diags);
    assert_eq!(descriptions.len(), 6);
    let analyzer = PyLanguageAnalyzer::new();
    assert!(
        analyzer.validate_syntax(Path::new("app/schemas.py"), &patched),
        "Patched Python source failed syntax validation:\n{patched}"
    );
    assert!(patched.contains("Field(default_factory=list)"));
    assert!(patched.contains("Field(default_factory=dict, description=\"meta\")"));
    assert!(patched.contains("Field(default_factory=set)"));
    assert!(patched.contains("Field(default_factory=lambda: datetime.now(timezone.utc))"));
    assert!(patched.contains("Field(default_factory=lambda: uuid4())"));
    assert!(patched.contains("bare_items: list[int] = Field(default_factory=list)"));

    let reanalyzed = analyze_source(
        Path::new("app/schemas.py"),
        &patched,
        Some(&[RuleId::PyPydanticPreferDefaultFactory]),
    );
    assert!(
        reanalyzed.is_empty(),
        "Expected 0 diagnostics after Autofix, got {reanalyzed:?}\nPatched:\n{patched}"
    );

    // Adversarial valid cases
    let valid_src = r#"from typing import ClassVar
from datetime import datetime, timezone
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

class UserOut(BaseModel):
    MODEL_VERSION: ClassVar[list[str]] = ["v1"]
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, str] = Field(default_factory=dict)
    roles: set[str] = Field(default_factory=set)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    request_id: UUID = Field(default_factory=uuid4)
    name: str = Field(default="anonymous")
    count: int = 0
"#;
    assert!(
        analyze_source(
            Path::new("app/valid_schemas.py"),
            valid_src,
            Some(&[RuleId::PyPydanticPreferDefaultFactory]),
        )
        .is_empty()
    );

    // Capability Gate check: requires Capability::Pydantic
    let python_only_gate = CapabilityGate::with_capabilities([Capability::Python]);
    assert!(
        analyze_source_with_config(
            Path::new("app/schemas.py"),
            invalid_src,
            &DotoreConfig::default(),
            &python_only_gate,
            None,
        )
        .is_empty()
    );
    let pydantic_gate =
        CapabilityGate::with_capabilities([Capability::Python, Capability::Pydantic]);
    assert_eq!(
        analyze_source_with_config(
            Path::new("app/schemas.py"),
            invalid_src,
            &DotoreConfig::default(),
            &pydantic_gate,
            Some(&[RuleId::PyPydanticPreferDefaultFactory]),
        )
        .len(),
        6
    );
}

#[test]
fn py_fastapi_require_response_model_flags_untyped_routes_and_allows_typed_or_response_model() {
    let invalid_src = r#"from typing import Any
from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter()

@app.get("/users/{user_id}")
async def get_user(user_id: int):
    return {"id": user_id}

@router.post("/users")
async def create_user(payload: dict) -> dict:
    return payload

@router.get("/raw")
def get_raw() -> Any:
    return {"ok": True}
"#;

    let diags = analyze_source(
        Path::new("app/routes.py"),
        invalid_src,
        Some(&[RuleId::PyFastapiRequireResponseModel]),
    );
    assert_eq!(diags.len(), 3, "Expected 3 diagnostics, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyFastapiRequireResponseModel);
    assert_eq!(diags[0].tier, PrescriptionTier::Surgical);
    assert_eq!(diags[0].subject_name.as_deref(), Some("get_user"));
    assert_eq!(diags[0].loc.line, 8);
    assert_eq!(diags[1].subject_name.as_deref(), Some("create_user"));
    assert_eq!(diags[1].loc.line, 12);
    assert_eq!(diags[2].subject_name.as_deref(), Some("get_raw"));
    assert_eq!(diags[2].loc.line, 16);

    let valid_src = r#"from fastapi import APIRouter, FastAPI, Response
from pydantic import BaseModel

app = FastAPI()
router = APIRouter()

class UserOut(BaseModel):
    id: int
    name: str

@app.get("/users/{user_id}", response_model=UserOut)
async def get_user_by_decorator(user_id: int):
    return {"id": user_id, "name": "Alice"}

@router.get("/users")
async def list_users() -> list[UserOut]:
    return []

@router.delete("/users/{user_id}", status_code=204)
async def delete_user(user_id: int) -> None:
    return None

@app.get("/health")
def health_check() -> Response:
    return Response(status_code=200)
"#;
    assert!(
        analyze_source(
            Path::new("app/valid_routes.py"),
            valid_src,
            Some(&[RuleId::PyFastapiRequireResponseModel]),
        )
        .is_empty()
    );

    // Capability Gate check: requires Capability::FastApi
    let python_only_gate = CapabilityGate::with_capabilities([Capability::Python]);
    assert!(
        analyze_source_with_config(
            Path::new("app/routes.py"),
            invalid_src,
            &DotoreConfig::default(),
            &python_only_gate,
            None,
        )
        .is_empty()
    );
    let fastapi_gate = CapabilityGate::with_capabilities([Capability::Python, Capability::FastApi]);
    assert_eq!(
        analyze_source_with_config(
            Path::new("app/routes.py"),
            invalid_src,
            &DotoreConfig::default(),
            &fastapi_gate,
            Some(&[RuleId::PyFastapiRequireResponseModel]),
        )
        .len(),
        3
    );
}

#[test]
fn py_fastapi_mutating_route_requires_auth_flags_unprotected_mutations_and_allows_auth_deps() {
    let invalid_src = r#"from fastapi import APIRouter, FastAPI
from pydantic import BaseModel

app = FastAPI()
router = APIRouter()

class OrderCreate(BaseModel):
    item_id: int
    quantity: int

@app.post("/orders")
async def create_order(payload: OrderCreate) -> OrderCreate:
    return payload

@router.delete("/orders/{order_id}", status_code=204)
async def delete_order(order_id: int) -> None:
    return None

@router.patch("/orders/{order_id}")
def update_order(order_id: int, payload: OrderCreate) -> OrderCreate:
    return payload
"#;

    let diags = analyze_source(
        Path::new("app/orders.py"),
        invalid_src,
        Some(&[RuleId::PyFastapiMutatingRouteRequiresAuth]),
    );
    assert_eq!(diags.len(), 3, "Expected 3 diagnostics, got {diags:?}");
    assert_eq!(diags[0].rule, RuleId::PyFastapiMutatingRouteRequiresAuth);
    assert_eq!(diags[0].tier, PrescriptionTier::Surgical);
    assert_eq!(diags[0].subject_name.as_deref(), Some("create_order"));
    assert_eq!(diags[0].loc.line, 12);
    assert_eq!(diags[1].subject_name.as_deref(), Some("delete_order"));
    assert_eq!(diags[1].loc.line, 16);
    assert_eq!(diags[2].subject_name.as_deref(), Some("update_order"));
    assert_eq!(diags[2].loc.line, 20);

    let valid_src = r#"from typing import Annotated
from fastapi import APIRouter, Depends, FastAPI, Security
from pydantic import BaseModel

app = FastAPI()
router = APIRouter()
protected_router = APIRouter(dependencies=[Depends(verify_token)])

class OrderOut(BaseModel):
    id: int

# Read-only GET routes do not require mutating auth
@app.get("/orders")
async def list_orders() -> list[OrderOut]:
    return []

# Public auth/webhook endpoints are exempt
@app.post("/auth/login")
async def login() -> OrderOut:
    return OrderOut(id=1)

@app.post("/webhooks/stripe")
async def stripe_webhook() -> OrderOut:
    return OrderOut(id=1)

# Protected via parameter Depends(get_current_user)
@router.post("/orders")
async def create_order(current_user: User = Depends(get_current_user)) -> OrderOut:
    return OrderOut(id=1)

# Protected via Annotated[..., Security(...)]
@router.put("/orders/{order_id}")
async def replace_order(
    order_id: int,
    user: Annotated[User, Security(get_current_active_user, scopes=["orders:write"])],
) -> OrderOut:
    return OrderOut(id=order_id)

# Protected via decorator dependencies=[Depends(...)]
@router.delete("/orders/{order_id}", dependencies=[Depends(require_admin)], status_code=204)
async def delete_order(order_id: int) -> None:
    return None

# Protected via router-level dependencies=[Depends(verify_token)]
@protected_router.post("/internal/reconcile")
async def reconcile_orders() -> OrderOut:
    return OrderOut(id=1)
"#;
    assert!(
        analyze_source(
            Path::new("app/valid_orders.py"),
            valid_src,
            Some(&[RuleId::PyFastapiMutatingRouteRequiresAuth]),
        )
        .is_empty()
    );

    // Capability Gate check: requires Capability::FastApi
    let python_only_gate = CapabilityGate::with_capabilities([Capability::Python]);
    assert!(
        analyze_source_with_config(
            Path::new("app/orders.py"),
            invalid_src,
            &DotoreConfig::default(),
            &python_only_gate,
            None,
        )
        .is_empty()
    );
}

#[test]
fn py_orm_no_query_in_loop_flags_sqlalchemy_and_django_n_plus_one_queries() {
    let invalid_src = r#"from sqlalchemy import select

def fetch_users_n_plus_one(session, db, user_ids: list[int], pending_ids: list[int]):
    users = []
    for uid in user_ids:
        row = session.query(User).filter(User.id == uid).first()
        scalar_user = session.scalars(select(User).where(User.id == uid)).one()
        django_user = User.objects.get(id=uid)
        orders = Order.objects.filter(user_id=uid).select_related("shop")
        users.append((row, scalar_user, django_user, orders))

    idx = 0
    while idx < len(pending_ids):
        item = db.execute(select(User).where(User.id == pending_ids[idx]))
        idx += 1
    return users
"#;

    let diags = analyze_source(
        Path::new("app/repositories.py"),
        invalid_src,
        Some(&[RuleId::PyOrmNoQueryInLoop]),
    );
    assert_eq!(diags.len(), 5, "Expected 5 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PyOrmNoQueryInLoop);
        assert_eq!(diag.tier, PrescriptionTier::Surgical);
        assert_eq!(diag.subject_name.as_deref(), Some("fetch_users_n_plus_one"));
    }
    assert_eq!(diags[0].loc.line, 6);
    assert_eq!(diags[1].loc.line, 7);
    assert_eq!(diags[2].loc.line, 8);
    assert_eq!(diags[3].loc.line, 9);
    assert_eq!(diags[4].loc.line, 14);

    let valid_src = r#"from sqlalchemy import select

def fetch_users_batched(session, user_ids: list[int]):
    users = session.scalars(select(User).where(User.id.in_(user_ids))).all()
    django_users = list(User.objects.filter(id__in=user_ids).select_related("profile"))
    by_id = {}
    for user in users:
        by_id[user.id] = user.name
    return by_id, django_users
"#;
    assert!(
        analyze_source(
            Path::new("app/valid_repositories.py"),
            valid_src,
            Some(&[RuleId::PyOrmNoQueryInLoop]),
        )
        .is_empty()
    );

    // Capability Gate check: activates when EITHER SqlAlchemy OR Django is present, skipped when neither is present
    let python_only_gate = CapabilityGate::with_capabilities([Capability::Python]);
    assert!(
        analyze_source_with_config(
            Path::new("app/repositories.py"),
            invalid_src,
            &DotoreConfig::default(),
            &python_only_gate,
            Some(&[RuleId::PyOrmNoQueryInLoop]),
        )
        .is_empty()
    );
    let sqlalchemy_gate =
        CapabilityGate::with_capabilities([Capability::Python, Capability::SqlAlchemy]);
    assert_eq!(
        analyze_source_with_config(
            Path::new("app/repositories.py"),
            invalid_src,
            &DotoreConfig::default(),
            &sqlalchemy_gate,
            Some(&[RuleId::PyOrmNoQueryInLoop]),
        )
        .len(),
        5
    );
    let django_gate = CapabilityGate::with_capabilities([Capability::Python, Capability::Django]);
    assert_eq!(
        analyze_source_with_config(
            Path::new("app/repositories.py"),
            invalid_src,
            &DotoreConfig::default(),
            &django_gate,
            Some(&[RuleId::PyOrmNoQueryInLoop]),
        )
        .len(),
        5
    );
}

#[test]
fn py_orm_no_query_in_loop_flags_lazy_relationship_access_unless_eager_loaded() {
    let invalid_lazy_src = r#"from sqlalchemy import select

def render_user_orders_and_posts(session):
    for user in session.scalars(select(User)):
        print(user.id, user.name)
        for order in user.orders:
            print(order)
        bio = user.profile.bio

    posts = Post.objects.all()
    for post in posts:
        comments = post.comments.all()
        author_org = post.author.organization
        print(post.title, comments, author_org)
"#;
    let diags = analyze_source(
        Path::new("app/lazy_n_plus_one.py"),
        invalid_lazy_src,
        Some(&[RuleId::PyOrmNoQueryInLoop]),
    );
    assert!(
        diags.len() >= 3,
        "Expected lazy relationship accesses (`user.orders`, `user.profile.bio`, `post.comments.all()`, `post.author.organization`) to be flagged, got: {diags:#?}"
    );
    assert!(diags.iter().all(|d| d.rule == RuleId::PyOrmNoQueryInLoop));

    let valid_eager_src = r#"from sqlalchemy import select
from sqlalchemy.orm import selectinload, joinedload

def render_eager_loaded(session):
    stmt = select(User).options(selectinload(User.orders), joinedload(User.profile))
    for user in session.scalars(stmt):
        for order in user.orders:
            print(order)
        print(user.profile.bio)

    for post in Post.objects.select_related("author").prefetch_related("comments"):
        print(post.comments.all(), post.author.organization)
"#;
    let valid_diags = analyze_source(
        Path::new("app/eager_loaded.py"),
        valid_eager_src,
        Some(&[RuleId::PyOrmNoQueryInLoop]),
    );
    assert!(
        valid_diags.is_empty(),
        "Expected 0 diagnostics when relationships are eager-loaded with selectinload/joinedload/select_related/prefetch_related, got: {valid_diags:#?}"
    );
}

#[test]
fn py_security_no_raw_sql_interpolation_flags_interpolated_sql_and_allows_parameterized() {
    let invalid_src = r#"from sqlalchemy import text
from django.db.models.expressions import RawSQL

def lookup_user_unsafe(cursor, session, conn, user_id: str, email: str):
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")
    session.execute("SELECT * FROM users WHERE email = '{}'".format(email))
    conn.execute("DELETE FROM sessions WHERE user_id = '%s'" % user_id)
    cursor.execute("SELECT * FROM audit_logs WHERE actor = '" + user_id + "'")
    stmt = text(f"SELECT * FROM accounts WHERE id = {user_id}")
    django_raw = User.objects.raw(f"SELECT * FROM auth_user WHERE username = '{email}'")
    expr = RawSQL(f"SELECT score FROM rankings WHERE uid = {user_id}", [])
    return stmt, django_raw, expr
"#;

    let diags = analyze_source(
        Path::new("app/sql_sinks.py"),
        invalid_src,
        Some(&[RuleId::PySecurityNoRawSqlInterpolation]),
    );
    assert_eq!(diags.len(), 7, "Expected 7 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PySecurityNoRawSqlInterpolation);
        assert_eq!(diag.tier, PrescriptionTier::Surgical);
        assert_eq!(diag.subject_name.as_deref(), Some("lookup_user_unsafe"));
    }
    assert_eq!(diags[0].loc.line, 5);
    assert_eq!(diags[1].loc.line, 6);
    assert_eq!(diags[2].loc.line, 7);
    assert_eq!(diags[3].loc.line, 8);
    assert_eq!(diags[4].loc.line, 9);
    assert_eq!(diags[5].loc.line, 10);
    assert_eq!(diags[6].loc.line, 11);

    let valid_src = r#"from sqlalchemy import text
from django.db.models.expressions import RawSQL

def lookup_user_safe(cursor, session, user_id: str, email: str):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    session.execute(
        text("SELECT * FROM users WHERE email = :email"),
        {"email": email},
    )
    django_raw = User.objects.raw("SELECT * FROM auth_user WHERE id = %s", [user_id])
    expr = RawSQL("SELECT score FROM rankings WHERE uid = %s", [user_id])
    return django_raw, expr
"#;
    assert!(
        analyze_source(
            Path::new("app/safe_sql.py"),
            valid_src,
            Some(&[RuleId::PySecurityNoRawSqlInterpolation]),
        )
        .is_empty()
    );

    // Capability Gate check: requires Capability::Python
    let react_only_gate = CapabilityGate::with_capabilities([Capability::React]);
    assert!(
        analyze_source_with_config(
            Path::new("app/sql_sinks.py"),
            invalid_src,
            &DotoreConfig::default(),
            &react_only_gate,
            None,
        )
        .is_empty()
    );
}

#[test]
fn py_security_no_unsafe_deserialization_or_shell_flags_sinks_and_autofixes_yaml_load() {
    let invalid_src = r#"import marshal
import os
import pickle
import subprocess
import yaml

def execute_and_deserialize_unsafe(cmd: str, raw_bytes: bytes, yaml_payload: str):
    subprocess.run(cmd, shell=True)
    os.system(cmd)
    eval(yaml_payload)
    exec(yaml_payload)
    obj1 = pickle.loads(raw_bytes)
    obj2 = marshal.loads(raw_bytes)
    cfg1 = yaml.load(yaml_payload)
    cfg2 = yaml.load(yaml_payload, Loader=yaml.Loader)
    return obj1, obj2, cfg1, cfg2
"#;

    let diags = analyze_source(
        Path::new("app/security_sinks.py"),
        invalid_src,
        Some(&[RuleId::PySecurityNoUnsafeDeserializationOrShell]),
    );
    assert_eq!(diags.len(), 8, "Expected 8 diagnostics, got {diags:?}");
    for diag in &diags {
        assert_eq!(diag.rule, RuleId::PySecurityNoUnsafeDeserializationOrShell);
        assert_eq!(diag.tier, PrescriptionTier::Autofix);
        assert_eq!(
            diag.subject_name.as_deref(),
            Some("execute_and_deserialize_unsafe")
        );
    }
    assert_eq!(diags[0].loc.line, 8);
    assert_eq!(diags[1].loc.line, 9);
    assert_eq!(diags[2].loc.line, 10);
    assert_eq!(diags[3].loc.line, 11);
    assert_eq!(diags[4].loc.line, 12);
    assert_eq!(diags[5].loc.line, 13);
    assert_eq!(diags[6].loc.line, 14);
    assert!(diags[6].autofix.is_some());
    assert_eq!(diags[7].loc.line, 15);
    assert!(diags[7].autofix.is_some());

    // Round-trip Autofix verification for yaml.load -> yaml.safe_load
    let yaml_only_src = r#"import yaml

def load_config(raw_yaml: str, fallback_yaml: str):
    primary = yaml.load(raw_yaml)
    secondary = yaml.load(fallback_yaml, Loader=yaml.UnsafeLoader)
    return primary, secondary
"#;
    let yaml_diags = analyze_source(
        Path::new("app/config_loader.py"),
        yaml_only_src,
        Some(&[RuleId::PySecurityNoUnsafeDeserializationOrShell]),
    );
    assert_eq!(yaml_diags.len(), 2);
    let (patched, descriptions) = apply_patches_to_source(yaml_only_src, &yaml_diags);
    assert_eq!(descriptions.len(), 2);
    let analyzer = PyLanguageAnalyzer::new();
    assert!(
        analyzer.validate_syntax(Path::new("app/config_loader.py"), &patched),
        "Patched Python source failed syntax validation:\n{patched}"
    );
    assert!(patched.contains("primary = yaml.safe_load(raw_yaml)"));
    assert!(patched.contains("secondary = yaml.safe_load(fallback_yaml)"));

    let reanalyzed = analyze_source(
        Path::new("app/config_loader.py"),
        &patched,
        Some(&[RuleId::PySecurityNoUnsafeDeserializationOrShell]),
    );
    assert!(
        reanalyzed.is_empty(),
        "Expected 0 diagnostics after Autofix, got {reanalyzed:?}\nPatched:\n{patched}"
    );

    // Adversarial valid cases
    let valid_src = r#"import subprocess
import yaml

def execute_and_load_safely(yaml_payload: str):
    subprocess.run(["ls", "-l"], check=True)
    subprocess.Popen(["echo", "ok"], shell=False)
    cfg1 = yaml.safe_load(yaml_payload)
    cfg2 = yaml.load(yaml_payload, Loader=yaml.SafeLoader)
    cfg3 = yaml.load(yaml_payload, Loader=yaml.CSafeLoader)
    return cfg1, cfg2, cfg3
"#;
    assert!(
        analyze_source(
            Path::new("app/safe_exec.py"),
            valid_src,
            Some(&[RuleId::PySecurityNoUnsafeDeserializationOrShell]),
        )
        .is_empty()
    );

    // Capability Gate check: requires Capability::Python
    let react_only_gate = CapabilityGate::with_capabilities([Capability::React]);
    assert!(
        analyze_source_with_config(
            Path::new("app/security_sinks.py"),
            invalid_src,
            &DotoreConfig::default(),
            &react_only_gate,
            None,
        )
        .is_empty()
    );
}

#[test]
fn analyze_project_sources_gates_web_orm_and_security_rules_by_pyproject_dependencies() {
    let pyproject = r#"
[project]
name = "backend-api"
dependencies = [
    "fastapi>=0.115.0",
    "pydantic>=2.9.0",
    "sqlalchemy>=2.0.0",
]
"#;
    let app_py = r#"from fastapi import FastAPI
from pydantic import BaseModel, Field
import yaml

app = FastAPI()

class ItemCreate(BaseModel):
    tags: list[str] = Field(default=[])

@app.post("/items")
async def create_item(session, ids: list[int], raw_cfg: str):
    cfg = yaml.load(raw_cfg)
    for item_id in ids:
        session.execute(f"SELECT * FROM items WHERE id = {item_id}")
    return cfg
"#;

    let report = analyze_project_sources(
        vec![
            (PathBuf::from("pyproject.toml"), pyproject.to_string()),
            (PathBuf::from("app/main.py"), app_py.to_string()),
        ],
        None,
    );
    let rules: Vec<RuleId> = report.diagnostics.iter().map(|d| d.rule).collect();
    assert!(rules.contains(&RuleId::PyPydanticPreferDefaultFactory));
    assert!(rules.contains(&RuleId::PyFastapiRequireResponseModel));
    assert!(rules.contains(&RuleId::PyFastapiMutatingRouteRequiresAuth));
    assert!(rules.contains(&RuleId::PyOrmNoQueryInLoop));
    assert!(rules.contains(&RuleId::PySecurityNoRawSqlInterpolation));
    assert!(rules.contains(&RuleId::PySecurityNoUnsafeDeserializationOrShell));
}
