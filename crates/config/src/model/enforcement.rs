use std::path::PathBuf;

use probe_core::{EnforcementMode, ProtectiveActionProfile, Selector};
use serde::{Deserialize, Serialize};

pub const DEFAULT_TRANSPARENT_INTERCEPTION_NFTABLES_TABLE: &str = "sssa_probe";
pub const DEFAULT_TRANSPARENT_INTERCEPTION_NFTABLES_MARK: u32 = 0x5353_4101;
pub const DEFAULT_TRANSPARENT_INTERCEPTION_ROUTE_TABLE: u32 = 53_534;

fn default_transparent_interception_nftables_table() -> String {
    DEFAULT_TRANSPARENT_INTERCEPTION_NFTABLES_TABLE.to_string()
}

fn default_transparent_interception_nftables_mark() -> u32 {
    DEFAULT_TRANSPARENT_INTERCEPTION_NFTABLES_MARK
}

fn default_transparent_interception_route_table() -> u32 {
    DEFAULT_TRANSPARENT_INTERCEPTION_ROUTE_TABLE
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementConfig {
    pub mode: EnforcementMode,
    pub backend: ConnectionEnforcementBackendConfig,
    pub selector: Option<Selector>,
    pub interception: EnforcementInterceptionConfig,
    pub policy: EnforcementPolicyConfig,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::AuditOnly,
            backend: ConnectionEnforcementBackendConfig::None,
            selector: None,
            interception: EnforcementInterceptionConfig::default(),
            policy: EnforcementPolicyConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionEnforcementBackendConfig {
    #[default]
    None,
    LinuxSocketDestroy,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementInterceptionConfig {
    pub strategy: TransparentInterceptionStrategyConfig,
    pub selector: Option<Selector>,
    pub proxy: TransparentInterceptionProxyConfig,
    pub nftables: TransparentInterceptionNftablesConfig,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransparentInterceptionStrategyConfig {
    #[default]
    None,
    InboundTproxy,
    OutboundMitm,
}

impl TransparentInterceptionStrategyConfig {
    pub fn is_enabled(self) -> bool {
        !matches!(self, Self::None)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionProxyConfig {
    pub listen_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransparentInterceptionNftablesConfig {
    #[serde(default = "default_transparent_interception_nftables_table")]
    pub table_name: String,
    #[serde(default = "default_transparent_interception_nftables_mark")]
    pub mark: u32,
    #[serde(default = "default_transparent_interception_route_table")]
    pub route_table: u32,
}

impl Default for TransparentInterceptionNftablesConfig {
    fn default() -> Self {
        Self {
            table_name: default_transparent_interception_nftables_table(),
            mark: default_transparent_interception_nftables_mark(),
            route_table: default_transparent_interception_route_table(),
        }
    }
}

impl TransparentInterceptionNftablesConfig {
    pub fn is_owned_table_name(value: &str) -> bool {
        is_nft_identifier(value) && value == DEFAULT_TRANSPARENT_INTERCEPTION_NFTABLES_TABLE
    }

    pub fn is_owned_mark(value: u32) -> bool {
        value == DEFAULT_TRANSPARENT_INTERCEPTION_NFTABLES_MARK
    }

    pub fn is_owned_route_table(value: u32) -> bool {
        value == DEFAULT_TRANSPARENT_INTERCEPTION_ROUTE_TABLE
    }
}

fn is_nft_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|char| char == '_' || char.is_ascii_alphanumeric())
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementPolicyConfig {
    pub source: EnforcementPolicySourceConfig,
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
