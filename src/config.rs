//! Project configuration loader (`dotore.config.*` and `package.json#dotore`),
//! workspace package discovery, and automatic **Capability Gate** inference.

use std::path::Path;

pub use dotore_core::config::{
    ArchitectureThresholdsConfig, Capability, CapabilityGate, CapabilityPredicate, ConfigMutation,
    ConfigTargetKind, DotoreConfig, IgnoreConfig, IgnoreOverride, MutateConfigResult, PackageRole,
    SupplyChainConfig, WorkspacePackage, discover_workspace_packages_with_analyzers,
    filter_workspace_packages, load_config_from_dir, mutate_config_in_dir,
    resolve_package_for_file,
};

/// Discovers all workspace packages under `root_dir` across all active [`crate::LanguageAnalyzer`]s,
/// computing each package's [`CapabilityGate`] and [`DotoreConfig`].
#[must_use]
pub fn discover_workspace_packages(root_dir: &Path) -> Vec<WorkspacePackage> {
    crate::register_active_core_hooks();
    discover_workspace_packages_with_analyzers(root_dir, crate::default_analyzers())
}
