//! Project configuration loader (`dotore.config.*` and `package.json#dotore`),
//! workspace package discovery, and automatic **Capability Gate** inference.

/// Project- and package-level **Capability Gate** inference.
pub mod capability_gate;
/// User configuration loader and static JS/TS/JSONC parser.
pub mod loader;
/// In-place configuration mutator (`dotore rules`).
pub mod mutator;
/// Workspace package discovery and path/JSONC normalization helpers.
pub mod workspace;

pub use capability_gate::{
    Capability, CapabilityGate, CapabilityPredicate, PackageRole, content_enables_react_compiler,
};
pub use loader::{
    ArchitectureThresholdsConfig, DotoreConfig, IgnoreConfig, IgnoreOverride, SupplyChainConfig,
    load_config_from_dir, load_local_config_in_dir,
};
pub use mutator::{ConfigMutation, ConfigTargetKind, MutateConfigResult, mutate_config_in_dir};
pub use workspace::{
    WorkspacePackage, discover_workspace_packages, discover_workspace_packages_with_analyzers,
    filter_workspace_packages, find_nearest_ancestor_file, is_cache_disabled, normalize_path_buf,
    normalize_rel_path_str, relative_forward_slash, resolve_dotore_home_dir,
    resolve_package_for_file, strip_jsonc, strip_source_extension, write_file_atomically,
};
