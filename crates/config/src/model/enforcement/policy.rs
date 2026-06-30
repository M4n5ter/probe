use std::{fmt, path::PathBuf};

use probe_core::{ProtectiveActionProfile, Selector};
use serde::{Deserialize, Deserializer, Serialize};

pub const DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_ENFORCEMENT_POLICY_RELOAD_WATCH_DEBOUNCE_MS: u64 = 500;
pub const MIN_ENFORCEMENT_POLICY_RELOAD_WATCH_DEBOUNCE_MS: u64 = 50;
pub const MAX_ENFORCEMENT_POLICY_RELOAD_WATCH_DEBOUNCE_MS: u64 = 60_000;
pub const DEFAULT_ENFORCEMENT_POLICY_RELOAD_REMOTE_POLL_INTERVAL_MS: u64 = 60_000;
pub const MIN_ENFORCEMENT_POLICY_RELOAD_REMOTE_POLL_INTERVAL_MS: u64 = 50;
pub const MAX_ENFORCEMENT_POLICY_RELOAD_REMOTE_POLL_INTERVAL_MS: u64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RemoteEnforcementPolicyBodyLimitBytes(u64);

impl RemoteEnforcementPolicyBodyLimitBytes {
    pub fn from_config(
        max_body_bytes: Option<u64>,
    ) -> Result<Self, RemoteEnforcementPolicyBodyLimitError> {
        max_body_bytes.map_or_else(|| Ok(Self::default()), Self::try_from)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Default for RemoteEnforcementPolicyBodyLimitBytes {
    fn default() -> Self {
        Self(DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES)
    }
}

impl TryFrom<u64> for RemoteEnforcementPolicyBodyLimitBytes {
    type Error = RemoteEnforcementPolicyBodyLimitError;

    fn try_from(limit: u64) -> Result<Self, Self::Error> {
        match limit {
            0 => Err(RemoteEnforcementPolicyBodyLimitError::Zero),
            limit if limit > MAX_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES => {
                Err(RemoteEnforcementPolicyBodyLimitError::ExceedsMaximum {
                    limit,
                    max: MAX_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES,
                })
            }
            limit => Ok(Self(limit)),
        }
    }
}

impl<'de> Deserialize<'de> for RemoteEnforcementPolicyBodyLimitBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let limit = u64::deserialize(deserializer)?;
        Self::try_from(limit).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemoteEnforcementPolicyBodyLimitError {
    Zero,
    ExceedsMaximum { limit: u64, max: u64 },
}

impl fmt::Display for RemoteEnforcementPolicyBodyLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => formatter
                .write_str("remote enforcement policy max_body_bytes must be greater than zero"),
            Self::ExceedsMaximum { limit, max } => write!(
                formatter,
                "remote enforcement policy max_body_bytes {limit} cannot exceed {max}"
            ),
        }
    }
}

impl std::error::Error for RemoteEnforcementPolicyBodyLimitError {}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementPolicyConfig {
    pub source: EnforcementPolicySourceConfig,
    pub reload: EnforcementPolicyReloadConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementPolicyReloadConfig {
    pub watch_local_manifest: bool,
    pub debounce_ms: u64,
    pub poll_remote_manifest: bool,
    pub remote_poll_interval_ms: u64,
}

impl Default for EnforcementPolicyReloadConfig {
    fn default() -> Self {
        Self {
            watch_local_manifest: false,
            debounce_ms: DEFAULT_ENFORCEMENT_POLICY_RELOAD_WATCH_DEBOUNCE_MS,
            poll_remote_manifest: false,
            remote_poll_interval_ms: DEFAULT_ENFORCEMENT_POLICY_RELOAD_REMOTE_POLL_INTERVAL_MS,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum EnforcementPolicySourceConfig {
    #[default]
    None,
    File {
        path: PathBuf,
    },
    Directory {
        path: PathBuf,
    },
    Remote {
        endpoint: String,
        max_body_bytes: Option<u64>,
    },
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementPolicyManifest {
    pub id: String,
    pub version: String,
    pub selector: Option<Selector>,
    pub protective_actions: ProtectiveActionProfile,
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, de::IntoDeserializer};

    use super::*;

    #[test]
    fn remote_policy_body_limit_resolves_default_and_explicit_config() {
        assert_eq!(
            RemoteEnforcementPolicyBodyLimitBytes::from_config(None)
                .expect("default remote body limit should be valid")
                .get(),
            DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES
        );
        assert_eq!(
            RemoteEnforcementPolicyBodyLimitBytes::from_config(Some(32 * 1024 * 1024))
                .expect("explicit remote body limit should be valid")
                .get(),
            32 * 1024 * 1024
        );
    }

    #[test]
    fn remote_policy_body_limit_rejects_out_of_range_config() {
        assert_eq!(
            RemoteEnforcementPolicyBodyLimitBytes::from_config(Some(0)),
            Err(RemoteEnforcementPolicyBodyLimitError::Zero)
        );
        assert_eq!(
            RemoteEnforcementPolicyBodyLimitBytes::from_config(Some(
                MAX_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES + 1,
            )),
            Err(RemoteEnforcementPolicyBodyLimitError::ExceedsMaximum {
                limit: MAX_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES + 1,
                max: MAX_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES,
            })
        );
    }

    #[test]
    fn remote_policy_body_limit_deserialization_preserves_bounds() {
        assert_eq!(
            deserialize_body_limit(DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES)
                .expect("default body limit must deserialize")
                .get(),
            DEFAULT_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES
        );
        assert!(deserialize_body_limit(0).is_err());
        assert!(
            deserialize_body_limit(MAX_REMOTE_ENFORCEMENT_POLICY_BODY_LIMIT_BYTES + 1).is_err()
        );
    }

    #[test]
    fn enforcement_policy_reload_config_defaults_to_no_background_watch() {
        assert_eq!(
            EnforcementPolicyReloadConfig::default(),
            EnforcementPolicyReloadConfig {
                watch_local_manifest: false,
                debounce_ms: DEFAULT_ENFORCEMENT_POLICY_RELOAD_WATCH_DEBOUNCE_MS,
                poll_remote_manifest: false,
                remote_poll_interval_ms: DEFAULT_ENFORCEMENT_POLICY_RELOAD_REMOTE_POLL_INTERVAL_MS,
            }
        );
    }

    fn deserialize_body_limit(
        limit: u64,
    ) -> Result<RemoteEnforcementPolicyBodyLimitBytes, serde::de::value::Error> {
        RemoteEnforcementPolicyBodyLimitBytes::deserialize(limit.into_deserializer())
    }
}
