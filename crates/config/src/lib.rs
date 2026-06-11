use std::{
    collections::{BTreeMap, HashSet},
    path::PathBuf,
};

use probe_core::{EnforcementMode, Selector};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const RESERVED_EXPORTER_HEADERS: &[&str] = &["content-type", "idempotency-key", "x-sssa-codec"];
const REPLAY_WEBHOOK_SINK_ID: &str = "replay-webhook";

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

        validate_capture(&self.capture, &mut violations);
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
    pub libpcap: LibpcapCaptureConfig,
    pub deep_observe_selector: Option<Selector>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LibpcapCaptureConfig {
    pub interface: Option<String>,
    pub bpf_filter: String,
    pub snaplen: i32,
    pub promisc: bool,
    pub immediate_mode: bool,
    pub read_timeout_ms: i32,
    pub buffer_size: Option<i32>,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            selection: CaptureSelection::Auto,
            fallback_backends: vec![LiveCaptureBackend::Ebpf, LiveCaptureBackend::Libpcap],
            libpcap: LibpcapCaptureConfig::default(),
            deep_observe_selector: None,
        }
    }
}

impl Default for LibpcapCaptureConfig {
    fn default() -> Self {
        Self {
            interface: None,
            bpf_filter: "tcp".to_string(),
            snaplen: 65_535,
            promisc: false,
            immediate_mode: true,
            read_timeout_ms: 1_000,
            buffer_size: None,
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

fn validate_capture(capture: &CaptureConfig, violations: &mut Vec<ConfigViolation>) {
    if capture.selection == CaptureSelection::Auto && capture.fallback_backends.is_empty() {
        violations.push(ConfigViolation {
            field: "capture.fallback_backends".to_string(),
            reason: "auto capture selection requires at least one live fallback backend"
                .to_string(),
        });
    }
    if capture_uses_libpcap(capture) {
        validate_libpcap_capture(&capture.libpcap, violations);
    }
}

fn capture_uses_libpcap(capture: &CaptureConfig) -> bool {
    match capture.selection {
        CaptureSelection::Libpcap => true,
        CaptureSelection::Auto => capture
            .fallback_backends
            .contains(&LiveCaptureBackend::Libpcap),
        CaptureSelection::Ebpf | CaptureSelection::Replay => false,
    }
}

fn validate_libpcap_capture(libpcap: &LibpcapCaptureConfig, violations: &mut Vec<ConfigViolation>) {
    if libpcap.bpf_filter.trim().is_empty() {
        violations.push(ConfigViolation {
            field: "capture.libpcap.bpf_filter".to_string(),
            reason: "libpcap BPF filter cannot be empty".to_string(),
        });
    }
    if libpcap.snaplen <= 0 {
        violations.push(ConfigViolation {
            field: "capture.libpcap.snaplen".to_string(),
            reason: "libpcap snaplen must be positive".to_string(),
        });
    }
    if libpcap.read_timeout_ms < 0 {
        violations.push(ConfigViolation {
            field: "capture.libpcap.read_timeout_ms".to_string(),
            reason: "libpcap read timeout cannot be negative".to_string(),
        });
    }
    if libpcap
        .buffer_size
        .is_some_and(|buffer_size| buffer_size <= 0)
    {
        violations.push(ConfigViolation {
            field: "capture.libpcap.buffer_size".to_string(),
            reason: "libpcap buffer size must be positive when set".to_string(),
        });
    }
}

fn validate_exporters(exporters: &[ExporterConfig], violations: &mut Vec<ConfigViolation>) {
    let mut ids = HashSet::new();
    for exporter in exporters {
        if exporter.id.trim().is_empty() {
            violations.push(ConfigViolation {
                field: "exporters.id".to_string(),
                reason: "exporter id cannot be empty".to_string(),
            });
        }
        if exporter.id == REPLAY_WEBHOOK_SINK_ID {
            violations.push(ConfigViolation {
                field: format!("exporters.{}.id", exporter.id),
                reason: "exporter id is reserved for replay CLI webhook output".to_string(),
            });
        }
        if !exporter.id.is_empty() && !ids.insert(exporter.id.as_str()) {
            violations.push(ConfigViolation {
                field: format!("exporters.{}.id", exporter.id),
                reason: "exporter id must be unique because it is used as the sink cursor key"
                    .to_string(),
            });
        }
        for (name, value) in &exporter.headers {
            if name.trim().is_empty() {
                violations.push(ConfigViolation {
                    field: format!("exporters.{}.headers", exporter.id),
                    reason: "exporter header name cannot be empty".to_string(),
                });
            } else if !valid_exporter_header_name(name) {
                violations.push(ConfigViolation {
                    field: format!("exporters.{}.headers.{}", exporter.id, name),
                    reason: "exporter header name is not a valid HTTP token".to_string(),
                });
            }
            if RESERVED_EXPORTER_HEADERS
                .iter()
                .any(|reserved| name.eq_ignore_ascii_case(reserved))
            {
                violations.push(ConfigViolation {
                    field: format!("exporters.{}.headers.{}", exporter.id, name),
                    reason: "exporter header is reserved by the webhook protocol".to_string(),
                });
            }
            if value.contains(['\r', '\n']) {
                violations.push(ConfigViolation {
                    field: format!("exporters.{}.headers.{}", exporter.id, name),
                    reason: "exporter header value cannot contain CR or LF".to_string(),
                });
            }
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
    if policies.iter().filter(|policy| policy.enabled).count() > 1 {
        violations.push(ConfigViolation {
            field: "policies".to_string(),
            reason: "runtime config currently supports at most one enabled policy bundle"
                .to_string(),
        });
    }
    for policy in policies {
        if policy.enabled && policy.path.as_os_str().is_empty() {
            violations.push(ConfigViolation {
                field: format!("policies.{}.path", policy.id),
                reason: "enabled policy must set a bundle/source path".to_string(),
            });
        }
    }
}

fn valid_exporter_header_name(name: &str) -> bool {
    !name.is_empty() && name.bytes().all(valid_http_token_byte)
}

fn valid_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
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
        assert_eq!(config.capture.libpcap.interface, None);
        assert_eq!(config.capture.libpcap.bpf_filter, "tcp");
        assert_eq!(config.capture.libpcap.snaplen, 65_535);
        assert!(!config.capture.libpcap.promisc);
        assert!(config.capture.libpcap.immediate_mode);
        assert_eq!(config.capture.libpcap.read_timeout_ms, 1_000);
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

[capture.libpcap]
interface = "lo"
bpf_filter = "tcp port 8080"
snaplen = 4096
promisc = true
immediate_mode = false
read_timeout_ms = 250
buffer_size = 1048576

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
        assert_eq!(config.capture.libpcap.interface.as_deref(), Some("lo"));
        assert_eq!(config.capture.libpcap.bpf_filter, "tcp port 8080");
        assert_eq!(config.capture.libpcap.snaplen, 4096);
        assert!(config.capture.libpcap.promisc);
        assert!(!config.capture.libpcap.immediate_mode);
        assert_eq!(config.capture.libpcap.read_timeout_ms, 250);
        assert_eq!(config.capture.libpcap.buffer_size, Some(1_048_576));
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

    #[test]
    fn validation_rejects_invalid_capture_runtime_fields() -> Result<(), Box<dyn std::error::Error>>
    {
        let empty_fallback = AgentConfig::from_toml_str(
            r#"
[capture]
fallback_backends = []
"#,
        )?;

        let empty_fallback_error = empty_fallback
            .validate_basic()
            .expect_err("auto capture requires a live backend");
        assert!(
            empty_fallback_error
                .to_string()
                .contains("auto capture selection requires at least one live fallback backend")
        );

        let config = AgentConfig::from_toml_str(
            r#"
[capture]
selection = "libpcap"

[capture.libpcap]
bpf_filter = " "
snaplen = 0
read_timeout_ms = -1
buffer_size = 0
"#,
        )?;

        let error = config
            .validate_basic()
            .expect_err("capture fields must be validated");

        assert!(
            error
                .to_string()
                .contains("libpcap BPF filter cannot be empty")
        );
        assert!(
            error
                .to_string()
                .contains("libpcap snaplen must be positive")
        );
        assert!(
            error
                .to_string()
                .contains("libpcap read timeout cannot be negative")
        );
        assert!(
            error
                .to_string()
                .contains("libpcap buffer size must be positive")
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_reserved_exporter_headers() -> Result<(), Box<dyn std::error::Error>> {
        let config = AgentConfig::from_toml_str(
            r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"
headers = { idempotency-key = "override" }
"#,
        )?;

        let error = config
            .validate_basic()
            .expect_err("reserved webhook header must be rejected");

        assert!(error.to_string().contains("exporter header is reserved"));
        Ok(())
    }

    #[test]
    fn validation_rejects_duplicate_and_reserved_exporter_ids()
    -> Result<(), Box<dyn std::error::Error>> {
        let duplicate = AgentConfig::from_toml_str(
            r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/one"

[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/two"
"#,
        )?;
        let duplicate_error = duplicate
            .validate_basic()
            .expect_err("duplicate exporter ids must be rejected");
        assert!(
            duplicate_error
                .to_string()
                .contains("exporter id must be unique")
        );

        let reserved = AgentConfig::from_toml_str(
            r#"
[[exporters]]
id = "replay-webhook"
transport = "webhook"
endpoint = "https://collector.example/replay"
"#,
        )?;
        let reserved_error = reserved
            .validate_basic()
            .expect_err("replay-webhook sink id must be reserved");
        assert!(
            reserved_error
                .to_string()
                .contains("reserved for replay CLI")
        );
        Ok(())
    }

    #[test]
    fn validation_rejects_invalid_exporter_headers() -> Result<(), Box<dyn std::error::Error>> {
        let config = AgentConfig::from_toml_str(
            r#"
[[exporters]]
id = "primary"
transport = "webhook"
endpoint = "https://collector.example/batches"
headers = { "bad header" = "value", good = "bad\nvalue" }
"#,
        )?;

        let error = config
            .validate_basic()
            .expect_err("invalid webhook headers must be rejected");

        assert!(
            error
                .to_string()
                .contains("exporter header name is not a valid HTTP token")
        );
        assert!(
            error
                .to_string()
                .contains("exporter header value cannot contain CR or LF")
        );
        Ok(())
    }

    #[test]
    fn validation_ignores_unused_libpcap_fields() -> Result<(), Box<dyn std::error::Error>> {
        let config = AgentConfig::from_toml_str(
            r#"
[capture]
selection = "replay"

[capture.libpcap]
bpf_filter = " "
snaplen = 0
"#,
        )?;

        config.validate_basic()?;
        Ok(())
    }

    #[test]
    fn validation_rejects_multiple_enabled_policies() -> Result<(), Box<dyn std::error::Error>> {
        let config = AgentConfig::from_toml_str(
            r#"
[[policies]]
id = "a"
enabled = true
path = "/tmp/a.lua"

[[policies]]
id = "b"
enabled = true
path = "/tmp/b.lua"
"#,
        )?;

        let error = config
            .validate_basic()
            .expect_err("multiple enabled policies must be rejected before run");

        assert!(
            error
                .to_string()
                .contains("at most one enabled policy bundle")
        );
        Ok(())
    }
}
