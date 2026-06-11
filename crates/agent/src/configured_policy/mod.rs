use std::path::{Path, PathBuf};

use policy::{POLICY_HOOKS, PolicyManifest, PolicyRuntime};
use probe_config::{AgentConfig, PolicyConfig};
use probe_core::{CompiledSelector, RuntimeMode};
use serde::Serialize;
use thiserror::Error;

pub const MAX_POLICY_SOURCE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub enum ConfiguredPolicyError {
    #[error("invalid policy source {path}: {reason}")]
    InvalidPolicySource { path: String, reason: String },
    #[error("failed to read policy file {path}: {source}")]
    ReadPolicy {
        path: String,
        source: std::io::Error,
    },
    #[error("policy error: {0}")]
    Policy(#[from] policy::PolicyError),
    #[error("invalid policy selector: {0}")]
    Selector(#[from] probe_core::SelectorError),
    #[error("unsupported policy config: {0}")]
    UnsupportedConfig(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfiguredPolicySelection {
    pub configured_count: u64,
    pub enabled_count: u64,
    pub active: Option<ConfiguredPolicySource>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConfiguredPolicySource {
    pub id: String,
    pub path: PathBuf,
    pub selector_configured: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicySourceInspection {
    pub mode: RuntimeMode,
    pub reason: Option<String>,
}

pub struct LoadedConfiguredPolicy {
    pub runtime: PolicyRuntime,
    pub source: ConfiguredPolicySource,
    pub selector: Option<CompiledSelector>,
}

pub fn configured_policy_selection(config: &AgentConfig) -> ConfiguredPolicySelection {
    let enabled = enabled_policies(config);
    ConfiguredPolicySelection {
        configured_count: config.policies.len() as u64,
        enabled_count: enabled.len() as u64,
        active: enabled
            .first()
            .map(|policy| configured_policy_source(policy)),
    }
}

pub fn load_configured_policy(
    config: &AgentConfig,
) -> Result<Option<LoadedConfiguredPolicy>, ConfiguredPolicyError> {
    let enabled = enabled_policies(config);
    match enabled.as_slice() {
        [] => Ok(None),
        [policy] => read_configured_policy(config, policy).map(Some),
        _ => Err(ConfiguredPolicyError::UnsupportedConfig(
            "live run currently supports at most one enabled policy bundle".to_string(),
        )),
    }
}

pub fn inspect_policy_source(path: &Path) -> PolicySourceInspection {
    match validate_policy_source(path) {
        Ok(()) => PolicySourceInspection {
            mode: RuntimeMode::Available,
            reason: None,
        },
        Err(error) => PolicySourceInspection {
            mode: RuntimeMode::Unavailable,
            reason: Some(error.reason()),
        },
    }
}

fn read_configured_policy(
    config: &AgentConfig,
    policy: &PolicyConfig,
) -> Result<LoadedConfiguredPolicy, ConfiguredPolicyError> {
    let selector = policy
        .selector
        .as_ref()
        .map(|selector| selector.compile())
        .transpose()?;
    let source = read_policy_source(&policy.path)?;
    let runtime = PolicyRuntime::from_source(
        PolicyManifest {
            id: policy.id.clone(),
            version: config.config_version.clone(),
            hooks: POLICY_HOOKS
                .iter()
                .map(|hook| hook.as_str().to_string())
                .collect(),
        },
        &source,
    )?;

    Ok(LoadedConfiguredPolicy {
        runtime,
        source: configured_policy_source(policy),
        selector,
    })
}

fn read_policy_source(path: &Path) -> Result<String, ConfiguredPolicyError> {
    validate_policy_source(path).map_err(|error| error.into_configured_error(path))?;

    std::fs::read_to_string(path).map_err(|source| ConfiguredPolicyError::ReadPolicy {
        path: path.display().to_string(),
        source,
    })
}

fn validate_policy_source(path: &Path) -> Result<(), PolicySourceValidationError> {
    let metadata = std::fs::metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            PolicySourceValidationError::NotFound
        } else {
            PolicySourceValidationError::Inspect(source)
        }
    })?;
    if !metadata.is_file() {
        return Err(PolicySourceValidationError::NotRegular);
    }
    if metadata.len() > MAX_POLICY_SOURCE_BYTES {
        return Err(PolicySourceValidationError::TooLarge(metadata.len()));
    }
    Ok(())
}

enum PolicySourceValidationError {
    NotFound,
    Inspect(std::io::Error),
    NotRegular,
    TooLarge(u64),
}

impl PolicySourceValidationError {
    fn reason(&self) -> String {
        match self {
            Self::NotFound => "policy source path does not exist".to_string(),
            Self::Inspect(error) => format!("failed to inspect policy source: {error}"),
            Self::NotRegular => "policy source path is not a regular file".to_string(),
            Self::TooLarge(size) => format!(
                "policy source is {size} bytes, exceeding the {MAX_POLICY_SOURCE_BYTES} byte limit"
            ),
        }
    }

    fn into_configured_error(self, path: &Path) -> ConfiguredPolicyError {
        match self {
            Self::Inspect(source) => ConfiguredPolicyError::ReadPolicy {
                path: path.display().to_string(),
                source,
            },
            error => ConfiguredPolicyError::InvalidPolicySource {
                path: path.display().to_string(),
                reason: error.reason(),
            },
        }
    }
}

fn configured_policy_source(policy: &PolicyConfig) -> ConfiguredPolicySource {
    ConfiguredPolicySource {
        id: policy.id.clone(),
        path: policy.path.clone(),
        selector_configured: policy.selector.is_some(),
    }
}

fn enabled_policies(config: &AgentConfig) -> Vec<&PolicyConfig> {
    config
        .policies
        .iter()
        .filter(|policy| policy.enabled)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        path::{Path, PathBuf},
    };

    use probe_config::AgentConfig;

    use super::*;

    #[test]
    fn load_configured_policy_rejects_non_file_source() -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-directory")?;
        let policy_path = temp.join("policy-dir");
        fs::create_dir_all(&policy_path)?;
        let config = config_with_policy(&policy_path)?;

        let Err(error) = load_configured_policy(&config) else {
            panic!("directory policy source must fail");
        };

        assert!(matches!(
            error,
            ConfiguredPolicyError::InvalidPolicySource { .. }
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    #[test]
    fn load_configured_policy_rejects_source_above_size_limit()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = test_dir("configured-policy-too-large")?;
        let policy_path = temp.join("guard.lua");
        let file = fs::File::create(&policy_path)?;
        file.set_len(MAX_POLICY_SOURCE_BYTES + 1)?;
        let config = config_with_policy(&policy_path)?;

        let Err(error) = load_configured_policy(&config) else {
            panic!("oversized policy source must fail");
        };

        assert!(matches!(
            error,
            ConfiguredPolicyError::InvalidPolicySource { .. }
        ));
        fs::remove_dir_all(temp)?;
        Ok(())
    }

    fn config_with_policy(path: &Path) -> Result<AgentConfig, probe_config::ConfigError> {
        AgentConfig::from_toml_str(&format!(
            r#"
agent_id = "agent-1"
config_version = "cfg-test"

[capture]
selection = "replay"

[[policies]]
id = "guard"
enabled = true
path = "{}"

[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"
codec = "none"
"#,
            path.display()
        ))
    }

    fn test_dir(name: &str) -> Result<PathBuf, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or_default()
        ));
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;
        Ok(path)
    }
}
