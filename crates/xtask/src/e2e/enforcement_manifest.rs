use std::{fs, path::Path};

use probe_config::EnforcementPolicyManifest;

pub(crate) fn write_enforcement_policy_manifest(
    path: &Path,
    manifest: &EnforcementPolicyManifest,
) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, toml::to_string(&manifest)?)?;
    Ok(())
}
