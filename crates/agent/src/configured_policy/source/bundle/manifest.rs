use std::fmt;

use policy::{PolicyHook, PolicyManifest};
use serde::Deserialize;

use super::modules::DeclaredModules;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::configured_policy::source) struct PolicyBundleManifest {
    id: String,
    version: String,
    hooks: Vec<PolicyHook>,
    #[serde(default)]
    modules: Vec<String>,
}

#[derive(Debug)]
pub(in crate::configured_policy::source) struct ValidPolicyBundleManifest {
    policy: PolicyManifest,
    modules: DeclaredModules,
}

#[derive(Debug)]
pub(in crate::configured_policy::source) enum PolicyBundleManifestError {
    EmptyId,
    EmptyVersion,
    IdMismatch { expected: String, actual: String },
    NoHooks,
    DuplicateHook(PolicyHook),
    Modules(String),
}

impl PolicyBundleManifest {
    pub(in crate::configured_policy::source) fn validate(
        self,
        expected_id: &str,
    ) -> Result<ValidPolicyBundleManifest, PolicyBundleManifestError> {
        if self.id.trim().is_empty() {
            return Err(PolicyBundleManifestError::EmptyId);
        }
        if self.version.trim().is_empty() {
            return Err(PolicyBundleManifestError::EmptyVersion);
        }
        if self.id != expected_id {
            return Err(PolicyBundleManifestError::IdMismatch {
                expected: expected_id.to_string(),
                actual: self.id,
            });
        }
        if self.hooks.is_empty() {
            return Err(PolicyBundleManifestError::NoHooks);
        }
        reject_duplicate_hooks(&self.hooks)?;

        Ok(ValidPolicyBundleManifest {
            policy: PolicyManifest {
                id: self.id,
                version: self.version,
                hooks: self.hooks,
            },
            modules: DeclaredModules::new(self.modules)
                .map_err(PolicyBundleManifestError::Modules)?,
        })
    }
}

impl ValidPolicyBundleManifest {
    pub(in crate::configured_policy::source) fn id(&self) -> &str {
        &self.policy.id
    }

    pub(in crate::configured_policy::source) fn version(&self) -> &str {
        &self.policy.version
    }

    pub(in crate::configured_policy::source) fn into_policy(self) -> PolicyManifest {
        self.policy
    }

    pub(in crate::configured_policy::source) fn modules(&self) -> &DeclaredModules {
        &self.modules
    }

    pub(in crate::configured_policy::source) fn module_count(&self) -> usize {
        self.modules.len()
    }
}

impl fmt::Display for PolicyBundleManifestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyId => formatter.write_str("policy id cannot be empty"),
            Self::EmptyVersion => formatter.write_str("policy version cannot be empty"),
            Self::IdMismatch { expected, actual } => write!(
                formatter,
                "policy bundle manifest id {actual} does not match configured policy id {expected}"
            ),
            Self::NoHooks => formatter.write_str("policy manifest must register at least one hook"),
            Self::DuplicateHook(hook) => {
                write!(formatter, "policy hook {hook} is registered more than once")
            }
            Self::Modules(reason) => formatter.write_str(reason),
        }
    }
}

fn reject_duplicate_hooks(hooks: &[PolicyHook]) -> Result<(), PolicyBundleManifestError> {
    let mut seen = Vec::<PolicyHook>::new();
    for hook in hooks {
        if seen.contains(hook) {
            return Err(PolicyBundleManifestError::DuplicateHook(*hook));
        }
        seen.push(*hook);
    }
    Ok(())
}
