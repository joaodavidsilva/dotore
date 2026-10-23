//! Project configuration loader (`dotore.config.*` and `package.json#dotore`),
//! workspace package discovery, and automatic **Capability Gate** inference.

pub use dotore_core::config::{
    Capability, CapabilityGate, CapabilityPredicate, ConfigMutation, ConfigTargetKind,
    DotoreConfig, IgnoreConfig, IgnoreOverride, MutateConfigResult, PackageRole, SupplyChainConfig,
    WorkspacePackage, content_enables_react_compiler, discover_workspace_packages,
    discover_workspace_packages_with_analyzers, load_config_from_dir, mutate_config_in_dir,
    resolve_package_for_file, strip_jsonc,
};
