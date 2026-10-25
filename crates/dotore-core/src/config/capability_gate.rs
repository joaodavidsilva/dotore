//! Project- and package-level **Capability Gate** inference across JavaScript/TypeScript,
//! Angular, Python, and Rust manifests.

use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::rules::{RuleMetadata, RuleTag};

use super::{
    find_nearest_ancestor_file, normalize_rel_path_str, relative_forward_slash, strip_jsonc,
    strip_source_extension,
};

const REACT_COMPILER_CONFIG_FILES: &[&str] = &[
    "next.config.js",
    "next.config.mjs",
    "next.config.ts",
    "next.config.cjs",
    "babel.config.js",
    "babel.config.json",
    "babel.config.cjs",
    "babel.config.mjs",
    "babel.config.ts",
    ".babelrc",
    ".babelrc.json",
    ".babelrc.js",
    "vite.config.ts",
    "vite.config.js",
    "vite.config.mjs",
    "app.json",
    "app.config.js",
    "app.config.ts",
];

const DEP_CAPABILITY_TABLE: &[(&str, &[Capability])] = &[
    ("react", &[Capability::React]),
    ("react-dom", &[Capability::React, Capability::Ssr]),
    (
        "next",
        &[
            Capability::React,
            Capability::Nextjs,
            Capability::ServerActions,
            Capability::Ssr,
        ],
    ),
    (
        "react-native",
        &[
            Capability::React,
            Capability::ReactNative,
            Capability::ClientOnly,
        ],
    ),
    (
        "expo",
        &[
            Capability::React,
            Capability::ReactNative,
            Capability::Expo,
            Capability::ClientOnly,
        ],
    ),
    (
        "expo-router",
        &[
            Capability::React,
            Capability::ReactNative,
            Capability::Expo,
            Capability::ClientOnly,
        ],
    ),
    (
        "gatsby",
        &[Capability::React, Capability::Ssr, Capability::ClientOnly],
    ),
    (
        "@remix-run/react",
        &[
            Capability::React,
            Capability::ServerActions,
            Capability::Ssr,
        ],
    ),
    (
        "@tanstack/react-start",
        &[
            Capability::React,
            Capability::TanstackStart,
            Capability::ServerActions,
            Capability::Ssr,
        ],
    ),
    ("@tanstack/react-query", &[Capability::TanstackQuery]),
    ("react-query", &[Capability::TanstackQuery]),
    (
        "react-scripts",
        &[Capability::React, Capability::ClientOnly],
    ),
    ("@astrojs/react", &[Capability::React]),
    ("vite", &[Capability::ClientOnly]),
    ("three", &[Capability::Three]),
    (
        "@react-three/fiber",
        &[Capability::React, Capability::Three, Capability::R3f],
    ),
    (
        "react-three-fiber",
        &[Capability::React, Capability::Three, Capability::R3f],
    ),
    ("@react-three/drei", &[Capability::Three]),
    ("@react-three/rapier", &[Capability::Three]),
    ("@react-three/postprocessing", &[Capability::Three]),
    ("@react-three/xr", &[Capability::Three]),
    ("@react-three/cannon", &[Capability::Three]),
    ("zustand", &[Capability::Zustand]),
    ("jotai", &[Capability::Jotai]),
    ("mobx", &[Capability::Mobx]),
    ("mobx-react", &[Capability::Mobx]),
    ("mobx-react-lite", &[Capability::Mobx]),
    ("mobx-state-tree", &[Capability::Mobx]),
    ("mobx-react-observer", &[Capability::Mobx]),
    ("valtio", &[Capability::Valtio]),
    ("preact", &[Capability::React, Capability::Preact]),
    ("ink", &[Capability::React, Capability::Ink]),
    ("zod", &[Capability::Zod]),
    ("framer-motion", &[Capability::Motion]),
    ("motion", &[Capability::Motion]),
    ("@react-spring/web", &[Capability::Motion]),
    ("react-spring", &[Capability::Motion]),
    ("react-native-reanimated", &[Capability::Motion]),
    ("gsap", &[Capability::Motion]),
    ("babel-plugin-react-compiler", &[Capability::ReactCompiler]),
    ("react-compiler-runtime", &[Capability::ReactCompiler]),
    ("eslint-plugin-react-compiler", &[Capability::ReactCompiler]),
    ("typescript", &[Capability::TypeScript]),
    ("tailwindcss", &[Capability::Tailwind]),
    ("react-router", &[Capability::React, Capability::ReactRouter]),
    ("react-router-dom", &[Capability::React, Capability::ReactRouter]),
    ("@react-router/dev", &[Capability::React, Capability::ReactRouter]),
    ("@react-router/node", &[Capability::React, Capability::ReactRouter]),
    ("@react-router/serve", &[Capability::React, Capability::ReactRouter]),
    ("remotion", &[Capability::React, Capability::Remotion]),
    ("@remotion/cli", &[Capability::React, Capability::Remotion]),
    ("@remotion/player", &[Capability::React, Capability::Remotion]),
    ("@remotion/renderer", &[Capability::React, Capability::Remotion]),
    ("react-redux", &[Capability::React, Capability::Redux]),
    ("@reduxjs/toolkit", &[Capability::Redux]),
    ("redux", &[Capability::Redux]),
    ("@tanstack/react-form", &[Capability::React, Capability::TanstackForm]),
    ("@tanstack/react-table", &[Capability::React, Capability::TanstackTable]),
    ("@tanstack/react-virtual", &[Capability::React, Capability::TanstackVirtual]),
    ("radix-ui", &[Capability::RadixUi]),
    ("@base-ui/react", &[Capability::BaseUi]),
    ("@base-ui-components/react", &[Capability::BaseUi]),
    ("react-aria-components", &[Capability::ReactAria]),
    ("styled-components", &[Capability::StyledComponents]),
    ("@angular/core", &[Capability::Angular, Capability::Rxjs, Capability::TypeScript]),
    ("@angular/common", &[Capability::Angular, Capability::TypeScript]),
    ("@angular/router", &[Capability::Angular, Capability::TypeScript]),
    ("@angular/forms", &[Capability::Angular, Capability::TypeScript]),
    ("@angular/platform-browser", &[Capability::Angular, Capability::TypeScript]),
    ("@angular/cdk", &[Capability::Angular, Capability::TypeScript]),
    ("@angular/material", &[Capability::Angular, Capability::AngularMaterial, Capability::TypeScript]),
    ("@ngrx/store", &[Capability::Angular, Capability::NgRx, Capability::Rxjs, Capability::TypeScript]),
    ("@ngrx/effects", &[Capability::Angular, Capability::NgRx, Capability::Rxjs, Capability::TypeScript]),
    ("@ngrx/entity", &[Capability::Angular, Capability::NgRx, Capability::TypeScript]),
    ("@ngrx/router-store", &[Capability::Angular, Capability::NgRx, Capability::TypeScript]),
    ("@ngrx/component-store", &[Capability::Angular, Capability::NgRx, Capability::Rxjs, Capability::TypeScript]),
    ("@ngrx/signals", &[Capability::Angular, Capability::NgRx, Capability::TypeScript]),
    ("@ngrx/operators", &[Capability::Angular, Capability::NgRx, Capability::Rxjs, Capability::TypeScript]),
    ("rxjs", &[Capability::Rxjs]),
];

/// Technology capability token inferred for a project or workspace package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    /// React runtime (`react`, `react-dom`, or React-backed framework).
    React,
    /// Next.js framework (`next`).
    Nextjs,
    /// React Native runtime (`react-native` or `expo`).
    ReactNative,
    /// Expo SDK (`expo`, `expo-router`).
    Expo,
    /// TanStack Query (`@tanstack/react-query`, `react-query`).
    TanstackQuery,
    /// TanStack Start (`@tanstack/react-start`).
    TanstackStart,
    /// Three.js 3D library (`three` or `@react-three/*`).
    Three,
    /// React Three Fiber (`@react-three/fiber`, `react-three-fiber`).
    R3f,
    /// Zustand state management (`zustand`).
    Zustand,
    /// Jotai atomic state management (`jotai`).
    Jotai,
    /// MobX reactive state (`mobx`, `mobx-react`, `mobx-react-lite`, `mobx-state-tree`).
    Mobx,
    /// Valtio proxy state (`valtio`).
    Valtio,
    /// Preact runtime (`preact`).
    Preact,
    /// Preact without `react` compatibility aliasing (`preact` present and `react` absent).
    PurePreact,
    /// Ink terminal UI (`ink`).
    Ink,
    /// Zod schema validation (`zod`).
    Zod,
    /// Motion / animation library (`framer-motion`, `motion`, `@react-spring/web`, `react-native-reanimated`, `gsap`).
    Motion,
    /// React Compiler (`babel-plugin-react-compiler`, `react-compiler-runtime`, `eslint-plugin-react-compiler`, or compiler config).
    ReactCompiler,
    /// Server Actions / Server Functions (`next`, `@tanstack/react-start`, `@remix-run/react`).
    ServerActions,
    /// Server-side rendering (`next`, `@remix-run/react`, `gatsby`, `@tanstack/react-start`, `react-dom`).
    Ssr,
    /// Client-only SPA or mobile runtime (`vite`, `react-scripts`, `react-native`, `expo`).
    ClientOnly,
    /// TypeScript language support (`typescript` or `.ts`/`.tsx` files).
    TypeScript,
    /// Tailwind CSS (`tailwindcss`).
    Tailwind,
    /// React Router (`react-router`, `react-router-dom`, `@react-router/*`).
    ReactRouter,
    /// Remotion video framework (`remotion`, `@remotion/*`).
    Remotion,
    /// Redux state management (`react-redux`, `@reduxjs/toolkit`, `redux`).
    Redux,
    /// TanStack Form (`@tanstack/react-form`).
    TanstackForm,
    /// TanStack Table (`@tanstack/react-table`).
    TanstackTable,
    /// TanStack Virtual (`@tanstack/react-virtual`).
    TanstackVirtual,
    /// Tailwind CSS v3.4+ (`tailwindcss` >= 3.4).
    #[serde(rename = "tailwind:3.4")]
    Tailwind34,
    /// Tailwind CSS v4+ (`tailwindcss` >= 4.0).
    #[serde(rename = "tailwind:4")]
    Tailwind4,
    /// Radix UI primitives (`radix-ui`, `@radix-ui/react-*`).
    RadixUi,
    /// Base UI primitives (`@base-ui/react`, `@base-ui-components/react`).
    BaseUi,
    /// React Aria Components (`react-aria-components`).
    ReactAria,
    /// shadcn/ui component conventions (`components.json` or shadcn dependencies).
    Shadcn,
    /// styled-components CSS-in-JS library (`styled-components`).
    StyledComponents,
    /// Angular framework (`@angular/core`, `angular.json`).
    Angular,
    /// RxJS reactive streams (`rxjs`).
    Rxjs,
    /// NgRx reactive state management (`@ngrx/store`, `@ngrx/effects`, `@ngrx/*`).
    #[serde(rename = "ngrx", alias = "ng-rx")]
    NgRx,
    /// Angular Material component library (`@angular/material`).
    AngularMaterial,
    /// Python language runtime (`.py`, `.pyi`, `pyproject.toml`, `requirements.txt`).
    Python,
    /// FastAPI web framework (`fastapi`).
    #[serde(rename = "fastapi", alias = "fast-api")]
    FastApi,
    /// Pydantic validation and settings library (`pydantic`).
    Pydantic,
    /// SQLAlchemy ORM (`sqlalchemy`).
    #[serde(rename = "sqlalchemy", alias = "sql-alchemy")]
    SqlAlchemy,
    /// Django web framework and ORM (`django`).
    Django,
    /// Python `asyncio` runtime and async ecosystem (`asyncio`, `anyio`, `aiohttp`, `httpx`, `uvicorn`).
    Asyncio,
    /// Pytest testing framework (`pytest`).
    Pytest,
    /// Rust language and Cargo crate (`Cargo.toml`, `.rs`).
    Rust,
    /// Tokio async runtime (`tokio`).
    Tokio,
    /// Axum web framework (`axum`).
    Axum,
    /// SQLx async SQL toolkit (`sqlx`).
    Sqlx,
    /// Serde serialization framework (`serde`, `serde_json`).
    Serde,
    /// Tracing structured instrumentation (`tracing`).
    Tracing,
    /// Leptos reactive Rust UI framework (`leptos`).
    Leptos,
    /// Dioxus reactive Rust UI framework (`dioxus`).
    Dioxus,
    /// Reqwest HTTP client (`reqwest`).
    Reqwest,
    /// Diesel ORM (`diesel`, `diesel-async`).
    Diesel,
    /// SeaORM async ORM (`sea-orm`, `sea-query`).
    SeaOrm,
    /// Rusqlite SQLite driver (`rusqlite`).
    Rusqlite,
    /// Postgres and Tokio-Postgres drivers (`postgres`, `tokio-postgres`).
    Postgres,
    /// Futures crate (`futures`, `futures-executor`, `futures-util`).
    Futures,
    /// Tower HTTP middleware (`tower-http`).
    TowerHttp,
    /// Actix CORS middleware (`actix-cors`).
    ActixCors,
    /// HTTP cookie management (`cookie`).
    Cookie,
    /// JSON Web Token verification (`jsonwebtoken`).
    Jsonwebtoken,
}

impl Capability {
    /// Returns the canonical kebab-case capability token string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::React => "react",
            Self::Nextjs => "nextjs",
            Self::ReactNative => "react-native",
            Self::Expo => "expo",
            Self::TanstackQuery => "tanstack-query",
            Self::TanstackStart => "tanstack-start",
            Self::Three => "three",
            Self::R3f => "r3f",
            Self::Zustand => "zustand",
            Self::Jotai => "jotai",
            Self::Mobx => "mobx",
            Self::Valtio => "valtio",
            Self::Preact => "preact",
            Self::PurePreact => "pure-preact",
            Self::Ink => "ink",
            Self::Zod => "zod",
            Self::Motion => "motion",
            Self::ReactCompiler => "react-compiler",
            Self::ServerActions => "server-actions",
            Self::Ssr => "ssr",
            Self::ClientOnly => "client-only",
            Self::TypeScript => "typescript",
            Self::Tailwind => "tailwind",
            Self::ReactRouter => "react-router",
            Self::Remotion => "remotion",
            Self::Redux => "redux",
            Self::TanstackForm => "tanstack-form",
            Self::TanstackTable => "tanstack-table",
            Self::TanstackVirtual => "tanstack-virtual",
            Self::Tailwind34 => "tailwind:3.4",
            Self::Tailwind4 => "tailwind:4",
            Self::RadixUi => "radix-ui",
            Self::BaseUi => "base-ui",
            Self::ReactAria => "react-aria",
            Self::Shadcn => "shadcn",
            Self::StyledComponents => "styled-components",
            Self::Angular => "angular",
            Self::Rxjs => "rxjs",
            Self::NgRx => "ngrx",
            Self::AngularMaterial => "angular-material",
            Self::Python => "python",
            Self::FastApi => "fastapi",
            Self::Pydantic => "pydantic",
            Self::SqlAlchemy => "sqlalchemy",
            Self::Django => "django",
            Self::Asyncio => "asyncio",
            Self::Pytest => "pytest",
            Self::Rust => "rust",
            Self::Tokio => "tokio",
            Self::Axum => "axum",
            Self::Sqlx => "sqlx",
            Self::Serde => "serde",
            Self::Tracing => "tracing",
            Self::Leptos => "leptos",
            Self::Dioxus => "dioxus",
            Self::Reqwest => "reqwest",
            Self::Diesel => "diesel",
            Self::SeaOrm => "sea-orm",
            Self::Rusqlite => "rusqlite",
            Self::Postgres => "postgres",
            Self::Futures => "futures",
            Self::TowerHttp => "tower-http",
            Self::ActixCors => "actix-cors",
            Self::Cookie => "cookie",
            Self::Jsonwebtoken => "jsonwebtoken",
        }
    }
}

/// Role of a package inferred from its manifest publish contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum PackageRole {
    /// Application package.
    Application,
    /// Published / consumable library package (`name` + `exports`/`main`/`module` and `private != true`).
    Library,
    /// Unclassified package (treated like an application so findings are not silently dropped).
    #[default]
    Unknown,
}

/// Predicate on a rule's metadata specifying which [`CapabilityGate`]s activate or disable it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CapabilityPredicate {
    /// Capabilities that must all be present in the package's [`CapabilityGate`].
    pub requires: &'static [Capability],
    /// Capabilities whose presence disables the rule (e.g. `ReactCompiler` for manual memoization rules).
    pub disabled_when: &'static [Capability],
    /// Whether this rule applies only to applications and should be skipped on library entrypoints.
    pub app_only: bool,
}

impl CapabilityPredicate {
    /// Predicate for rules that require only `Capability::React`.
    pub const REACT_ONLY: Self = Self {
        requires: &[Capability::React],
        disabled_when: &[],
        app_only: false,
    };
    /// Predicate for rules that require `Capability::Angular`.
    pub const ANGULAR_ONLY: Self = Self {
        requires: &[Capability::Angular],
        disabled_when: &[],
        app_only: false,
    };
    /// Predicate for rules that require `Capability::Python`.
    pub const PYTHON_ONLY: Self = Self {
        requires: &[Capability::Python],
        disabled_when: &[],
        app_only: false,
    };
    /// Predicate for rules that require `Capability::Rust`.
    pub const RUST_ONLY: Self = Self {
        requires: &[Capability::Rust],
        disabled_when: &[],
        app_only: false,
    };
    /// Predicate for universal rules with no framework requirement.
    pub const UNIVERSAL: Self = Self {
        requires: &[],
        disabled_when: &[],
        app_only: false,
    };

    /// Constructs a predicate requiring all capabilities in `requires`.
    #[must_use]
    pub const fn require(requires: &'static [Capability]) -> Self {
        Self {
            requires,
            disabled_when: &[],
            app_only: false,
        }
    }
}

/// Project- or package-level technology profile inferred from declared dependencies and configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityGate {
    /// Active capability tokens for this package.
    #[serde(serialize_with = "serialize_sorted_capabilities")]
    pub capabilities: HashSet<Capability>,
    /// Inferred package role (`Application`, `Library`, or `Unknown`).
    pub package_role: PackageRole,
    /// Relative entrypoint paths declared in `package.json` (`exports`, `main`, `module`, `source`).
    #[serde(serialize_with = "serialize_sorted_paths")]
    pub entrypoints: HashSet<PathBuf>,
    /// Combined dependency map (`name -> version spec`).
    #[serde(serialize_with = "serialize_sorted_deps")]
    pub dependencies: HashMap<String, String>,
    /// Whether React Compiler is enabled for this package.
    pub has_react_compiler: bool,
}

fn serialize_sorted_capabilities<S>(
    caps: &HashSet<Capability>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut sorted: Vec<Capability> = caps.iter().copied().collect();
    sorted.sort_by_key(|c| c.as_str());
    serializer.collect_seq(sorted)
}

fn serialize_sorted_paths<S>(paths: &HashSet<PathBuf>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut sorted: Vec<&PathBuf> = paths.iter().collect();
    sorted.sort();
    serializer.collect_seq(sorted)
}

fn serialize_sorted_deps<S>(
    deps: &HashMap<String, String>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut sorted: Vec<(&String, &String)> = deps.iter().collect();
    sorted.sort_by_key(|(a, _)| *a);
    serializer.collect_map(sorted)
}
impl Default for CapabilityGate {
    fn default() -> Self {
        Self::default_react()
    }
}

impl CapabilityGate {
    /// Empty [`CapabilityGate`] with no active capabilities.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            capabilities: HashSet::new(),
            package_role: PackageRole::Unknown,
            entrypoints: HashSet::new(),
            dependencies: HashMap::new(),
            has_react_compiler: false,
        }
    }

    /// Default capability gate for standalone React/TypeScript source analysis when no `package.json` is present.
    #[must_use]
    pub fn default_react() -> Self {
        Self::with_capabilities([
            Capability::React,
            Capability::TypeScript,
            Capability::Tailwind,
            Capability::Tailwind34,
            Capability::Tailwind4,
            Capability::RadixUi,
            Capability::BaseUi,
            Capability::ReactAria,
            Capability::Shadcn,
            Capability::StyledComponents,
        ])
    }

    /// Default capability gate for standalone Angular/TypeScript source analysis.
    #[must_use]
    pub fn default_angular() -> Self {
        Self::with_capabilities([
            Capability::Angular,
            Capability::Rxjs,
            Capability::TypeScript,
            Capability::NgRx,
            Capability::AngularMaterial,
        ])
    }

    /// Default capability gate for standalone Python source analysis when no `pyproject.toml` or `requirements.txt` is present.
    #[must_use]
    pub fn default_python() -> Self {
        Self::with_capabilities([
            Capability::Python,
            Capability::Asyncio,
            Capability::FastApi,
            Capability::Pydantic,
            Capability::SqlAlchemy,
            Capability::Django,
            Capability::Pytest,
        ])
    }

    /// Default capability gate for standalone Rust source analysis when no `Cargo.toml` is present.
    #[must_use]
    pub fn default_rust() -> Self {
        Self::with_capabilities([
            Capability::Rust,
            Capability::Tokio,
            Capability::Axum,
            Capability::Sqlx,
            Capability::Serde,
            Capability::Tracing,
            Capability::Leptos,
            Capability::Dioxus,
            Capability::Reqwest,
            Capability::Diesel,
            Capability::SeaOrm,
            Capability::Rusqlite,
            Capability::Postgres,
            Capability::Futures,
            Capability::TowerHttp,
            Capability::ActixCors,
            Capability::Cookie,
            Capability::Jsonwebtoken,
        ])
    }

    /// Constructs a [`CapabilityGate`] from an explicit iterator of [`Capability`] tokens.
    #[must_use]
    pub fn with_capabilities<I: IntoIterator<Item = Capability>>(iter: I) -> Self {
        let capabilities: HashSet<Capability> = iter.into_iter().collect();
        let has_react_compiler = capabilities.contains(&Capability::ReactCompiler);
        Self {
            capabilities,
            package_role: PackageRole::Unknown,
            entrypoints: HashSet::new(),
            dependencies: HashMap::new(),
            has_react_compiler,
        }
    }

    /// Merges capabilities, entrypoints, dependencies, and package role from `other` into `self`.
    pub fn merge(&mut self, other: &Self) {
        self.capabilities.extend(other.capabilities.iter().copied());
        self.entrypoints.extend(other.entrypoints.iter().cloned());
        for (k, v) in &other.dependencies {
            self.dependencies
                .entry(k.clone())
                .or_insert_with(|| v.clone());
        }
        if self.package_role == PackageRole::Unknown && other.package_role != PackageRole::Unknown {
            self.package_role = other.package_role;
        }
        if other.has_react_compiler {
            self.has_react_compiler = true;
            self.capabilities.insert(Capability::ReactCompiler);
        }
    }

    /// Returns `true` if `cap` is active in this gate.
    #[must_use]
    pub fn has(&self, cap: Capability) -> bool {
        self.capabilities.contains(&cap)
    }

    /// Infers a [`CapabilityGate`] from a `package.json` JSON string.
    #[must_use]
    pub fn from_package_json_str(json: &str) -> Self {
        serde_json::from_str::<Value>(&strip_jsonc(json)).map_or_else(
            |_| Self::default_react(),
            |v| Self::from_package_json_value(&v, None),
        )
    }

    /// Discovers a [`CapabilityGate`] for `package_dir` by reading its `package.json`, `angular.json`, and compiler configs.
    #[must_use]
    pub fn discover(package_dir: &Path) -> Self {
        let has_angular_json = package_dir.join("angular.json").is_file()
            || find_nearest_ancestor_file(package_dir, "angular.json").is_some();
        let pkg_path = package_dir
            .join("package.json")
            .is_file()
            .then(|| package_dir.join("package.json"))
            .or_else(|| find_nearest_ancestor_file(package_dir, "package.json"));

        let mut gate = pkg_path
            .and_then(|p| fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str::<Value>(&strip_jsonc(&s)).ok())
            .map_or_else(
                || {
                    if has_angular_json {
                        Self::default_angular()
                    } else {
                        Self::default_react()
                    }
                },
                |v| Self::from_package_json_value(&v, Some(package_dir)),
            );

        if has_angular_json {
            gate.capabilities.insert(Capability::Angular);
            gate.capabilities.insert(Capability::Rxjs);
            gate.capabilities.insert(Capability::TypeScript);
        }
        if !gate.has_react_compiler && detect_react_compiler_in_dir(package_dir) {
            gate.has_react_compiler = true;
            gate.capabilities.insert(Capability::ReactCompiler);
        }
        gate
    }

    fn from_package_json_value(val: &Value, package_dir: Option<&Path>) -> Self {
        let dependencies = collect_package_dependencies(val);
        let mut capabilities = if dependencies.is_empty() {
            HashSet::from([Capability::React, Capability::TypeScript])
        } else {
            infer_capabilities_from_deps(&dependencies)
        };
        if val.get("tsconfig").is_some()
            || package_dir.is_some_and(|d| d.join("tsconfig.json").is_file())
        {
            capabilities.insert(Capability::TypeScript);
        }
        if package_dir
            .and_then(|d| find_nearest_ancestor_file(d, "components.json"))
            .is_some()
        {
            capabilities.insert(Capability::Shadcn);
        }
        if val
            .get("reactCompiler")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || val
                .get("babel")
                .is_some_and(|b| b.to_string().contains("react-compiler"))
        {
            capabilities.insert(Capability::ReactCompiler);
        }
        let has_react_compiler = capabilities.contains(&Capability::ReactCompiler);
        let (package_role, entrypoints) = extract_package_role_and_entrypoints(val);
        Self {
            capabilities,
            package_role,
            entrypoints,
            dependencies,
            has_react_compiler,
        }
    }

    /// Checks whether a rule's [`RuleMetadata`] is satisfied by this [`CapabilityGate`].
    #[must_use]
    pub fn allows_rule(&self, meta: &RuleMetadata) -> bool {
        let pred = &meta.capability_gate;
        let has_py_orm_or = pred.requires.contains(&Capability::SqlAlchemy)
            && pred.requires.contains(&Capability::Django);
        let has_rust_ui_or = pred.requires.contains(&Capability::Leptos)
            && pred.requires.contains(&Capability::Dioxus);
        let has_rust_sql_or = pred.requires.contains(&Capability::Sqlx)
            && pred.requires.contains(&Capability::Diesel);
        let has_rust_cors_or = pred.requires.contains(&Capability::TowerHttp)
            && pred.requires.contains(&Capability::ActixCors);
        let has_rust_async_or = pred.requires.contains(&Capability::Tokio)
            && pred.requires.contains(&Capability::Futures);
        let has_any_rust_cap = self.capabilities.contains(&Capability::Rust)
            || self.capabilities.iter().any(|c| {
                matches!(
                    c,
                    Capability::Tokio
                        | Capability::Axum
                        | Capability::Sqlx
                        | Capability::Serde
                        | Capability::Tracing
                        | Capability::Leptos
                        | Capability::Dioxus
                        | Capability::Reqwest
                        | Capability::Diesel
                        | Capability::SeaOrm
                        | Capability::Rusqlite
                        | Capability::Postgres
                        | Capability::Futures
                        | Capability::TowerHttp
                        | Capability::ActixCors
                        | Capability::Cookie
                        | Capability::Jsonwebtoken
                )
            });
        let requires_ok = pred.requires.iter().all(|req| {
            if has_py_orm_or && matches!(req, Capability::SqlAlchemy | Capability::Django) {
                self.capabilities.contains(&Capability::SqlAlchemy)
                    || self.capabilities.contains(&Capability::Django)
            } else if has_rust_ui_or && matches!(req, Capability::Leptos | Capability::Dioxus) {
                self.capabilities.contains(&Capability::Leptos)
                    || self.capabilities.contains(&Capability::Dioxus)
            } else if has_rust_sql_or
                && matches!(
                    req,
                    Capability::Sqlx
                        | Capability::Diesel
                        | Capability::SeaOrm
                        | Capability::Rusqlite
                        | Capability::Postgres
                )
            {
                self.capabilities.contains(&Capability::Sqlx)
                    || self.capabilities.contains(&Capability::Diesel)
                    || self.capabilities.contains(&Capability::SeaOrm)
                    || self.capabilities.contains(&Capability::Rusqlite)
                    || self.capabilities.contains(&Capability::Postgres)
            } else if has_rust_cors_or && matches!(req, Capability::TowerHttp | Capability::ActixCors)
            {
                self.capabilities.contains(&Capability::TowerHttp)
                    || self.capabilities.contains(&Capability::ActixCors)
            } else if has_rust_async_or && matches!(req, Capability::Tokio | Capability::Futures) {
                self.capabilities.contains(&Capability::Tokio)
                    || self.capabilities.contains(&Capability::Futures)
            } else if *req == Capability::Rust {
                has_any_rust_cap
            } else {
                self.capabilities.contains(req)
            }
        });
        requires_ok
            && (!meta.tags.contains(&RuleTag::ReactJsxOnly)
                || self.capabilities.contains(&Capability::React))
            && pred
                .disabled_when
                .iter()
                .all(|dis| !self.capabilities.contains(dis))
    }

    /// Returns `true` if `file_path` is a library entrypoint in a `PackageRole::Library` package.
    #[must_use]
    pub fn is_library_entrypoint(&self, file_path: &Path, package_dir: &Path) -> bool {
        if self.package_role != PackageRole::Library {
            return false;
        }
        if self.entrypoints.is_empty() {
            return true;
        }
        let rel_norm = relative_forward_slash(file_path, package_dir);
        let rel_stem = strip_source_extension(&rel_norm);
        if matches!(
            rel_stem,
            "index" | "src/index" | "lib/index" | "src/main" | "main"
        ) {
            return true;
        }
        self.entrypoints.iter().any(|entry| {
            let entry_norm = normalize_rel_path_str(entry);
            let entry_stem = strip_source_extension(&entry_norm);
            rel_stem == entry_stem
                || entry_stem
                    .strip_prefix("dist/")
                    .or_else(|| entry_stem.strip_prefix("build/"))
                    .or_else(|| entry_stem.strip_prefix("lib/"))
                    .is_some_and(|s| rel_stem == s || rel_stem == format!("src/{s}"))
        })
    }
}

fn collect_package_dependencies(val: &Value) -> HashMap<String, String> {
    let mut deps = HashMap::new();
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        let Some(obj) = val.get(section).and_then(Value::as_object) else {
            continue;
        };
        for (k, v) in obj {
            if let Some(ver) = v.as_str() {
                deps.entry(k.clone()).or_insert_with(|| ver.to_string());
            }
        }
    }
    deps
}

fn infer_capabilities_from_deps(deps: &HashMap<String, String>) -> HashSet<Capability> {
    let mut caps = HashSet::new();
    for &(pkg_name, mapped_caps) in DEP_CAPABILITY_TABLE {
        if deps.contains_key(pkg_name) {
            caps.extend(mapped_caps.iter().copied());
        }
    }
    if deps.keys().any(|k| k.starts_with("@angular/")) {
        caps.insert(Capability::Angular);
        caps.insert(Capability::TypeScript);
    }
    if deps.keys().any(|k| k.starts_with("@ngrx/")) {
        caps.insert(Capability::NgRx);
        caps.insert(Capability::Angular);
        caps.insert(Capability::TypeScript);
    }
    if deps.contains_key("preact") && !deps.contains_key("react") {
        caps.insert(Capability::PurePreact);
    }
    if deps.keys().any(|k| {
        k == "radix-ui" || (k.starts_with("@radix-ui/react-") && k != "@radix-ui/react-icons")
    }) {
        caps.insert(Capability::RadixUi);
    }
    if deps.contains_key("shadcn")
        || deps.contains_key("shadcn-ui")
        || deps.contains_key("class-variance-authority")
    {
        caps.insert(Capability::Shadcn);
    }
    if deps
        .keys()
        .any(|k| k == "react-router" || k == "react-router-dom" || k.starts_with("@react-router/"))
    {
        caps.insert(Capability::React);
        caps.insert(Capability::ReactRouter);
    }
    if deps
        .keys()
        .any(|k| k == "remotion" || k.starts_with("@remotion/"))
    {
        caps.insert(Capability::React);
        caps.insert(Capability::Remotion);
    }
    if let Some(tw_ver) = deps.get("tailwindcss") {
        let parsed = parse_major_minor_spec(tw_ver);
        if parsed.is_none_or(|(maj, min)| maj > 3 || (maj == 3 && min >= 4)) {
            caps.insert(Capability::Tailwind34);
        }
        if parsed.is_some_and(|(maj, _)| maj >= 4) {
            caps.insert(Capability::Tailwind4);
        }
    }
    caps
}

fn parse_major_minor_spec(spec: &str) -> Option<(u32, u32)> {
    let trimmed = spec.trim();
    let start = trimmed.find(|c: char| c.is_ascii_digit())?;
    let rest = &trimmed[start..];
    let mut parts = rest.split(|c: char| !c.is_ascii_digit());
    let major = parts.next()?.parse::<u32>().ok()?;
    let minor = parts
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    Some((major, minor))
}

fn extract_package_role_and_entrypoints(val: &Value) -> (PackageRole, HashSet<PathBuf>) {
    let mut entrypoints = HashSet::new();
    if let Some(exports_val) = val.get("exports") {
        collect_export_paths(exports_val, &mut entrypoints);
    }
    for field in ["main", "module", "source"] {
        if let Some(s) = val.get(field).and_then(Value::as_str) {
            let clean = s.trim().trim_start_matches("./");
            if !clean.is_empty() {
                entrypoints.insert(PathBuf::from(clean));
            }
        }
    }
    let has_name = val
        .get("name")
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty());
    let is_private = val.get("private").and_then(Value::as_bool).unwrap_or(false);
    let has_publish_surface =
        !entrypoints.is_empty() || val.get("exports").is_some_and(|v| !v.is_null());
    let role = if has_name && !is_private && has_publish_surface {
        PackageRole::Library
    } else if is_private {
        PackageRole::Application
    } else {
        PackageRole::Unknown
    };
    (role, entrypoints)
}

fn collect_export_paths(val: &Value, out: &mut HashSet<PathBuf>) {
    match val {
        Value::String(s) => {
            let clean = s.trim().trim_start_matches("./");
            if !clean.is_empty() {
                out.insert(PathBuf::from(clean));
            }
        }
        Value::Array(arr) => arr.iter().for_each(|v| collect_export_paths(v, out)),
        Value::Object(map) => map.values().for_each(|v| collect_export_paths(v, out)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn detect_react_compiler_in_dir(dir: &Path) -> bool {
    REACT_COMPILER_CONFIG_FILES.iter().any(|name| {
        fs::read_to_string(dir.join(name)).is_ok_and(|c| content_enables_react_compiler(&c))
    })
}

/// Checks whether a config file's text enables React Compiler (`reactCompiler: true`, `babel-plugin-react-compiler`).
#[must_use]
pub fn content_enables_react_compiler(content: &str) -> bool {
    if content.contains("babel-plugin-react-compiler") || content.contains("react-compiler-runtime")
    {
        return true;
    }
    content.find("reactCompiler").is_some_and(|idx| {
        let after = content.get(idx + "reactCompiler".len()..).unwrap_or_default();
        let trimmed = after.trim_start_matches([':', ' ', '\t', '\n', '\r', '"', '\'']);
        trimmed.starts_with("true") || trimmed.starts_with('{')
    })
}
