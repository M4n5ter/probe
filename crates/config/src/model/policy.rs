use std::{fmt, path::PathBuf};

use probe_core::Selector;
use serde::{Deserialize, Deserializer, Serialize};

pub const DEFAULT_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES: u64 = 512 * 1024 * 1024;
pub const DEFAULT_POLICY_RELOAD_WATCH_DEBOUNCE_MS: u64 = 500;
pub const MIN_POLICY_RELOAD_WATCH_DEBOUNCE_MS: u64 = 50;
pub const MAX_POLICY_RELOAD_WATCH_DEBOUNCE_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RemotePolicyBundleBodyLimitBytes(u64);

impl RemotePolicyBundleBodyLimitBytes {
    pub fn from_config(
        max_body_bytes: Option<u64>,
    ) -> Result<Self, RemotePolicyBundleBodyLimitError> {
        max_body_bytes.map_or_else(|| Ok(Self::default()), Self::try_from)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

impl Default for RemotePolicyBundleBodyLimitBytes {
    fn default() -> Self {
        Self(DEFAULT_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES)
    }
}

impl TryFrom<u64> for RemotePolicyBundleBodyLimitBytes {
    type Error = RemotePolicyBundleBodyLimitError;

    fn try_from(limit: u64) -> Result<Self, Self::Error> {
        match limit {
            0 => Err(RemotePolicyBundleBodyLimitError::Zero),
            limit if limit > MAX_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES => {
                Err(RemotePolicyBundleBodyLimitError::ExceedsMaximum {
                    limit,
                    max: MAX_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES,
                })
            }
            limit => Ok(Self(limit)),
        }
    }
}

impl<'de> Deserialize<'de> for RemotePolicyBundleBodyLimitBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let limit = u64::deserialize(deserializer)?;
        Self::try_from(limit).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemotePolicyBundleBodyLimitError {
    Zero,
    ExceedsMaximum { limit: u64, max: u64 },
}

impl fmt::Display for RemotePolicyBundleBodyLimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Zero => {
                formatter.write_str("remote policy bundle max_body_bytes must be greater than zero")
            }
            Self::ExceedsMaximum { limit, max } => write!(
                formatter,
                "remote policy bundle max_body_bytes {limit} cannot exceed {max}"
            ),
        }
    }
}

impl std::error::Error for RemotePolicyBundleBodyLimitError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyReloadConfig {
    pub watch_local_bundles: bool,
    pub debounce_ms: u64,
}

impl Default for PolicyReloadConfig {
    fn default() -> Self {
        Self {
            watch_local_bundles: false,
            debounce_ms: DEFAULT_POLICY_RELOAD_WATCH_DEBOUNCE_MS,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub id: String,
    pub source: PolicySourceConfig,
    pub enabled: bool,
    pub selector: Option<Selector>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            source: PolicySourceConfig::default(),
            enabled: true,
            selector: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", deny_unknown_fields)]
pub enum PolicySourceConfig {
    LocalDirectory {
        path: PathBuf,
    },
    RemoteBundle {
        endpoint: String,
        max_body_bytes: Option<u64>,
    },
}

impl Default for PolicySourceConfig {
    fn default() -> Self {
        Self::LocalDirectory {
            path: PathBuf::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, de::IntoDeserializer};

    use super::*;

    #[test]
    fn remote_policy_bundle_body_limit_resolves_default_and_explicit_config() {
        assert_eq!(
            RemotePolicyBundleBodyLimitBytes::from_config(None)
                .expect("default remote body limit should be valid")
                .get(),
            DEFAULT_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES
        );
        assert_eq!(
            RemotePolicyBundleBodyLimitBytes::from_config(Some(32 * 1024 * 1024))
                .expect("explicit remote body limit should be valid")
                .get(),
            32 * 1024 * 1024
        );
    }

    #[test]
    fn remote_policy_bundle_body_limit_rejects_out_of_range_config() {
        assert_eq!(
            RemotePolicyBundleBodyLimitBytes::from_config(Some(0)),
            Err(RemotePolicyBundleBodyLimitError::Zero)
        );
        assert_eq!(
            RemotePolicyBundleBodyLimitBytes::from_config(Some(
                MAX_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES + 1,
            )),
            Err(RemotePolicyBundleBodyLimitError::ExceedsMaximum {
                limit: MAX_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES + 1,
                max: MAX_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES,
            })
        );
    }

    #[test]
    fn remote_policy_bundle_body_limit_deserialization_preserves_bounds() {
        assert_eq!(
            deserialize_body_limit(DEFAULT_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES)
                .expect("default body limit must deserialize")
                .get(),
            DEFAULT_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES
        );
        assert!(deserialize_body_limit(0).is_err());
        assert!(deserialize_body_limit(MAX_REMOTE_POLICY_BUNDLE_BODY_LIMIT_BYTES + 1).is_err());
    }

    #[test]
    fn policy_reload_config_defaults_to_no_background_watch() {
        assert_eq!(
            PolicyReloadConfig::default(),
            PolicyReloadConfig {
                watch_local_bundles: false,
                debounce_ms: DEFAULT_POLICY_RELOAD_WATCH_DEBOUNCE_MS,
            }
        );
    }

    fn deserialize_body_limit(
        limit: u64,
    ) -> Result<RemotePolicyBundleBodyLimitBytes, serde::de::value::Error> {
        RemotePolicyBundleBodyLimitBytes::deserialize(limit.into_deserializer())
    }
}
