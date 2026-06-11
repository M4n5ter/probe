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
    pub export: ExportRuntimeConfig,
    pub exporters: Vec<ExporterConfig>,
    pub policies: Vec<PolicyConfig>,
    pub tls: TlsConfig,
    pub enforcement: EnforcementConfig,
    pub admin: AdminConfig,
}

impl AgentConfig {
    pub fn from_toml_str(content: &str) -> Result<Self, ConfigError> {
        toml::from_str(content).map_err(ConfigError::Toml)
    }

    pub fn validate_basic(&self) -> Result<(), ConfigError> {
        let mut violations = Vec::new();

        validate_capture(&self.capture, &mut violations);
        validate_tls(&self.tls, &self.capture, &mut violations);
        validate_export_runtime(&self.export, &mut violations);
        validate_exporters(&self.exporters, &mut violations);
        validate_policies(&self.policies, &mut violations);
        validate_admin(&self.admin, &mut violations);

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
            export: ExportRuntimeConfig::default(),
            exporters: Vec::new(),
            policies: Vec::new(),
            tls: TlsConfig::default(),
            enforcement: EnforcementConfig::default(),
            admin: AdminConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CaptureConfig {
    pub selection: CaptureSelection,
    pub fallback_backends: Vec<LiveCaptureBackend>,
    pub libpcap: LibpcapCaptureConfig,
    pub plaintext_feed: PlaintextFeedCaptureConfig,
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
            plaintext_feed: PlaintextFeedCaptureConfig::default(),
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
pub struct PlaintextFeedCaptureConfig {
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSelection {
    Auto,
    Ebpf,
    Libpcap,
    PlaintextFeed,
    Replay,
}

impl CaptureSelection {
    pub fn explicit_backend(self) -> Option<CaptureBackend> {
        match self {
            Self::Auto => None,
            Self::Ebpf => Some(CaptureBackend::Ebpf),
            Self::Libpcap => Some(CaptureBackend::Libpcap),
            Self::PlaintextFeed => Some(CaptureBackend::PlaintextFeed),
            Self::Replay => Some(CaptureBackend::Replay),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureBackend {
    Ebpf,
    Libpcap,
    PlaintextFeed,
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
pub struct ExportRuntimeConfig {
    pub worker_enabled: bool,
    pub worker_interval_ms: u64,
}

impl Default for ExportRuntimeConfig {
    fn default() -> Self {
        Self {
            worker_enabled: true,
            worker_interval_ms: 1_000,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AdminConfig {
    pub enabled: bool,
    pub socket_path: PathBuf,
}

impl Default for AdminConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            socket_path: PathBuf::from("/run/sssa-probe/admin.sock"),
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
    validate_plaintext_feed_capture(capture, violations);
}

fn capture_uses_libpcap(capture: &CaptureConfig) -> bool {
    match capture.selection {
        CaptureSelection::Libpcap => true,
        CaptureSelection::Auto => capture
            .fallback_backends
            .contains(&LiveCaptureBackend::Libpcap),
        CaptureSelection::Ebpf | CaptureSelection::PlaintextFeed | CaptureSelection::Replay => {
            false
        }
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

fn validate_plaintext_feed_capture(capture: &CaptureConfig, violations: &mut Vec<ConfigViolation>) {
    match capture.selection {
        CaptureSelection::PlaintextFeed => {
            if capture.plaintext_feed.path.is_none() {
                violations.push(ConfigViolation {
                    field: "capture.plaintext_feed.path".to_string(),
                    reason: "plaintext feed capture requires a JSON-lines feed path".to_string(),
                });
            }
        }
        CaptureSelection::Auto
        | CaptureSelection::Ebpf
        | CaptureSelection::Libpcap
        | CaptureSelection::Replay => {
            if capture.plaintext_feed.path.is_some() {
                violations.push(ConfigViolation {
                    field: "capture.plaintext_feed.path".to_string(),
                    reason: "plaintext feed path is only valid when capture.selection = \"plaintext_feed\""
                        .to_string(),
                });
            }
        }
    }
}

fn validate_tls(tls: &TlsConfig, capture: &CaptureConfig, violations: &mut Vec<ConfigViolation>) {
    validate_tls_materials(tls, violations);

    if capture.selection == CaptureSelection::PlaintextFeed {
        validate_plaintext_feed_selection(tls, violations);
    }

    if !tls.plaintext.enabled {
        return;
    }

    match tls.plaintext.provider {
        TlsPlaintextProvider::LibsslUprobe | TlsPlaintextProvider::Keylog => {}
    }
}

fn validate_tls_materials(tls: &TlsConfig, violations: &mut Vec<ConfigViolation>) {
    for (index, material) in tls.materials.iter().enumerate() {
        if material.path.as_os_str().is_empty() {
            violations.push(ConfigViolation {
                field: format!("tls.materials[{index}].path"),
                reason: "TLS material path cannot be empty".to_string(),
            });
        }
    }
}

fn validate_plaintext_feed_selection(tls: &TlsConfig, violations: &mut Vec<ConfigViolation>) {
    if !tls.plaintext.enabled {
        return;
    }

    violations.push(ConfigViolation {
        field: "tls.plaintext.enabled".to_string(),
        reason: "plaintext_feed capture is the external plaintext source; disable tls.plaintext or select a TLS instrumentation backend"
            .to_string(),
    });
}

fn validate_export_runtime(export: &ExportRuntimeConfig, violations: &mut Vec<ConfigViolation>) {
    if export.worker_enabled && export.worker_interval_ms == 0 {
        violations.push(ConfigViolation {
            field: "export.worker_interval_ms".to_string(),
            reason: "export worker interval must be positive when the worker is enabled"
                .to_string(),
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

fn validate_admin(admin: &AdminConfig, violations: &mut Vec<ConfigViolation>) {
    if !admin.enabled {
        return;
    }
    if admin.socket_path.as_os_str().is_empty() {
        violations.push(ConfigViolation {
            field: "admin.socket_path".to_string(),
            reason: "enabled admin socket requires a socket path".to_string(),
        });
    } else if !admin.socket_path.is_absolute() {
        violations.push(ConfigViolation {
            field: "admin.socket_path".to_string(),
            reason: "admin socket path must be absolute".to_string(),
        });
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
mod tests;
