use std::{collections::BTreeMap, path::PathBuf};

use probe_core::Selector;
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to parse TOML config: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid config: {0}")]
    Validation(#[from] ConfigValidationError),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentConfig {
    pub agent_id: String,
    pub config_version: String,
    pub capture: CaptureConfig,
    pub storage: StorageConfig,
    pub exporters: Vec<ExporterConfig>,
    pub policies: Vec<PolicyConfig>,
    pub tls: TlsConfig,
    pub enforcement: EnforcementConfig,
}

impl AgentConfig {
    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(ConfigError::Toml)
    }

    pub fn validate_basic(&self) -> Result<(), ConfigError> {
        let mut violations = Vec::new();

        validate_exporters(&self.exporters, &mut violations);
        validate_policies(&self.policies, &mut violations);

        if violations.is_empty() {
            Ok(())
        } else {
            Err(ConfigValidationError { violations }.into())
        }
    }
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            agent_id: "sssa-probe".to_string(),
            config_version: "local".to_string(),
            capture: CaptureConfig::default(),
            storage: StorageConfig::default(),
            exporters: Vec::new(),
            policies: Vec::new(),
            tls: TlsConfig::default(),
            enforcement: EnforcementConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    pub selection: CaptureSelection,
    pub fallback_backends: Vec<LiveCaptureBackend>,
    pub deep_observe_selector: Option<Selector>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            selection: CaptureSelection::Auto,
            fallback_backends: vec![LiveCaptureBackend::Ebpf, LiveCaptureBackend::Libpcap],
            deep_observe_selector: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSelection {
    Auto,
    Ebpf,
    Libpcap,
    Replay,
}

impl CaptureSelection {
    pub fn explicit_backend(self) -> Option<CaptureBackend> {
        match self {
            Self::Auto => None,
            Self::Ebpf => Some(CaptureBackend::Ebpf),
            Self::Libpcap => Some(CaptureBackend::Libpcap),
            Self::Replay => Some(CaptureBackend::Replay),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureBackend {
    Ebpf,
    Libpcap,
    Replay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveCaptureBackend {
    Ebpf,
    Libpcap,
}

impl From<LiveCaptureBackend> for CaptureBackend {
    fn from(value: LiveCaptureBackend) -> Self {
        match value {
            LiveCaptureBackend::Ebpf => Self::Ebpf,
            LiveCaptureBackend::Libpcap => Self::Libpcap,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub path: PathBuf,
    pub ingress_retention_bytes: Option<u64>,
    pub export_retention_bytes: Option<u64>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("/var/lib/sssa-probe/spool"),
            ingress_retention_bytes: None,
            export_retention_bytes: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ExporterConfig {
    pub id: String,
    pub transport: ExporterTransport,
    pub endpoint: String,
    pub codec: CompressionCodecName,
    pub headers: BTreeMap<String, String>,
}

impl Default for ExporterConfig {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            transport: ExporterTransport::Webhook,
            endpoint: String::new(),
            codec: CompressionCodecName::Zstd,
            headers: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExporterTransport {
    Webhook,
    Grpc,
    Kafka,
    Otlp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompressionCodecName {
    None,
    Zstd,
    Gzip,
    Deflate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PolicyConfig {
    pub id: String,
    pub path: PathBuf,
    pub enabled: bool,
    pub selector: Option<Selector>,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            id: "default".to_string(),
            path: PathBuf::new(),
            enabled: true,
            selector: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct TlsConfig {
    pub plaintext: PlaintextTlsConfig,
    pub materials: Vec<TlsMaterialConfig>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PlaintextTlsConfig {
    pub enabled: bool,
    pub provider: TlsPlaintextProvider,
}

impl Default for PlaintextTlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: TlsPlaintextProvider::LibsslUprobe,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsPlaintextProvider {
    LibsslUprobe,
    Keylog,
    ExternalFeed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsMaterialConfig {
    pub kind: TlsMaterialKind,
    pub path: PathBuf,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMaterialKind {
    TrustAnchor,
    ClientCertificate,
    ClientPrivateKey,
    KeyLogFile,
    SessionSecretFile,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct EnforcementConfig {
    pub mode: EnforcementMode,
    pub selector: Option<Selector>,
}

impl Default for EnforcementConfig {
    fn default() -> Self {
        Self {
            mode: EnforcementMode::AuditOnly,
            selector: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Disabled,
    AuditOnly,
    DryRun,
    Enforce,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigValidationError {
    violations: Vec<ConfigViolation>,
}

impl ConfigValidationError {
    pub fn new(violations: Vec<ConfigViolation>) -> Self {
        Self { violations }
    }

    pub fn violations(&self) -> &[ConfigViolation] {
        &self.violations
    }
}

impl std::fmt::Display for ConfigValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (index, violation) in self.violations.iter().enumerate() {
            if index > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{}: {}", violation.field, violation.reason)?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigValidationError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigViolation {
    pub field: String,
    pub reason: String,
}

fn validate_exporters(exporters: &[ExporterConfig], violations: &mut Vec<ConfigViolation>) {
    for exporter in exporters {
        if exporter.id.trim().is_empty() {
            violations.push(ConfigViolation {
                field: "exporters.id".to_string(),
                reason: "exporter id cannot be empty".to_string(),
            });
        }
        match exporter.transport {
            ExporterTransport::Webhook => {
                if exporter.endpoint.trim().is_empty() {
                    violations.push(ConfigViolation {
                        field: format!("exporters.{}.endpoint", exporter.id),
                        reason: "webhook endpoint cannot be empty".to_string(),
                    });
                }
            }
            ExporterTransport::Grpc | ExporterTransport::Kafka | ExporterTransport::Otlp => {}
        }
    }
}

fn validate_policies(policies: &[PolicyConfig], violations: &mut Vec<ConfigViolation>) {
    for policy in policies {
        if policy.enabled && policy.path.as_os_str().is_empty() {
            violations.push(ConfigViolation {
                field: format!("policies.{}.path", policy.id),
                reason: "enabled policy must set a bundle/source path".to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_uses_defaults() -> Result<(), Box<dyn std::error::Error>> {
        let config = AgentConfig::from_toml_str("")?;

        assert_eq!(config.agent_id, "sssa-probe");
        assert_eq!(config.capture.selection, CaptureSelection::Auto);
        assert_eq!(
            config.capture.fallback_backends,
            vec![LiveCaptureBackend::Ebpf, LiveCaptureBackend::Libpcap]
        );
        assert_eq!(config.exporters, Vec::<ExporterConfig>::new());
        assert_eq!(config.enforcement.mode, EnforcementMode::AuditOnly);
        config.validate_basic()?;
        Ok(())
    }

    #[test]
    fn parses_runtime_sections() -> Result<(), Box<dyn std::error::Error>> {
        let config = AgentConfig::from_toml_str(
            r#"
agent_id = "node-a"
config_version = "cfg-1"

[capture]
selection = "ebpf"
fallback_backends = ["libpcap"]

[storage]
path = "/tmp/sssa-spool"
ingress_retention_bytes = 1048576

[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"
codec = "zstd"
headers = { x_probe = "node-a" }

[[tls.materials]]
kind = "trust_anchor"
path = "/etc/ssl/certs/ca.pem"

[tls.plaintext]
enabled = true
provider = "libssl_uprobe"

[enforcement]
mode = "dry_run"
"#,
        )?;

        assert_eq!(config.agent_id, "node-a");
        assert_eq!(config.config_version, "cfg-1");
        assert_eq!(config.capture.selection, CaptureSelection::Ebpf);
        assert_eq!(config.storage.path, PathBuf::from("/tmp/sssa-spool"));
        assert_eq!(config.exporters[0].codec, CompressionCodecName::Zstd);
        assert_eq!(config.tls.materials[0].kind, TlsMaterialKind::TrustAnchor);
        assert!(config.tls.plaintext.enabled);
        assert_eq!(config.enforcement.mode, EnforcementMode::DryRun);
        Ok(())
    }

    #[test]
    fn config_rejects_unknown_fields() {
        let result = AgentConfig::from_toml_str("unknown = true");

        assert!(result.is_err());
    }
}
