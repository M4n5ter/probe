use attribution::{ProcessAttributor, ProcfsAttributor, ProcfsSocketResolver};
use probe_config::{
    AgentConfig, CaptureBackend, CaptureSelection, CompressionCodecName, ConfigError,
    ConfigValidationError, ConfigViolation, EnforcementPolicySourceConfig,
    ExportWorkerScheduleConfig, ExporterTlsConfig, ExporterTransport, LiveCaptureBackend,
    TlsMaterialConfig, TlsMaterialKind, TlsPlaintextProvider,
};
use probe_core::{CapabilityKind, CapabilityMatrix, CapabilityState, EnforcementMode, RuntimeMode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroU64;
use std::path::PathBuf;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error("config error: {0}")]
    Config(#[from] ConfigError),
    #[error("runtime config validation failed: {0}")]
    Validation(#[from] ConfigValidationError),
    #[error("no live capture provider is available: {reason}")]
    NoLiveCapture { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimePlan {
    pub config: AgentConfig,
    pub capabilities: CapabilityMatrix,
    pub capture: CapturePlan,
    pub tls: TlsPlan,
    pub export: ExportPlan,
    pub enforcement: EnforcementPlan,
}

impl RuntimePlan {
    pub fn build(config: AgentConfig, registry: &ProviderRegistry) -> Result<Self, RuntimeError> {
        config.validate_basic()?;
        validate_runtime_config(&config, registry)?;
        let capabilities = registry.capability_matrix();
        let capture = CapturePlan::resolve(&config, registry);
        let tls = TlsPlan::resolve(&config, &capabilities);
        let export = ExportPlan::resolve(&config);
        let enforcement = EnforcementPlan::resolve(&config);
        Ok(Self {
            config,
            capabilities,
            capture,
            tls,
            export,
            enforcement,
        })
    }

    pub fn require_live_capture(&self) -> Result<(), RuntimeError> {
        if self.capture.mode == CapturePlanMode::Live {
            Ok(())
        } else {
            Err(RuntimeError::NoLiveCapture {
                reason: self
                    .capture
                    .reason
                    .clone()
                    .unwrap_or_else(|| "capture plan did not select a live backend".to_string()),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPlan {
    pub plaintext: TlsPlaintextPlan,
}

impl TlsPlan {
    fn resolve(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        Self {
            plaintext: TlsPlaintextPlan::resolve(config, capabilities),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsPlaintextPlan {
    pub enabled: bool,
    pub provider: TlsPlaintextProvider,
    pub selector_configured: bool,
    pub capability: TlsPlaintextCapabilityPlan,
    pub key_logs: Vec<TlsPlaintextMaterialPlan>,
    pub session_secrets: Vec<TlsPlaintextMaterialPlan>,
}

impl TlsPlaintextPlan {
    fn resolve(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        let materials_by_id = tls_plaintext_materials_by_id(&config.tls.materials);
        Self {
            enabled: config.tls.plaintext.enabled,
            provider: config.tls.plaintext.provider,
            selector_configured: config.tls.plaintext.selector.is_some(),
            capability: TlsPlaintextCapabilityPlan::from_config(config, capabilities),
            key_logs: tls_plaintext_materials_from_refs(
                &config.tls.plaintext.key_log_refs,
                TlsMaterialKind::KeyLogFile,
                &materials_by_id,
            ),
            session_secrets: tls_plaintext_materials_from_refs(
                &config.tls.plaintext.session_secret_refs,
                TlsMaterialKind::SessionSecretFile,
                &materials_by_id,
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TlsPlaintextCapabilityPlan {
    NotRequired,
    Required {
        capability: CapabilityKind,
        mode: RuntimeMode,
    },
}

impl TlsPlaintextCapabilityPlan {
    fn from_config(config: &AgentConfig, capabilities: &CapabilityMatrix) -> Self {
        if !config.tls.plaintext.enabled {
            return Self::NotRequired;
        }
        match config.tls.plaintext.provider {
            TlsPlaintextProvider::LibsslUprobe => Self::Required {
                capability: CapabilityKind::LibsslUprobe,
                mode: capabilities.mode(CapabilityKind::LibsslUprobe),
            },
            TlsPlaintextProvider::Keylog => {
                unreachable!("runtime validation rejects keylog plaintext provider before planning")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsMaterialPlan {
    pub id: String,
    pub kind: TlsMaterialKind,
    pub path: PathBuf,
}

pub type TlsPlaintextMaterialPlan = TlsMaterialPlan;
pub type ExportTlsMaterialPlan = TlsMaterialPlan;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementPlan {
    pub mode: EnforcementMode,
    pub config_selector_configured: bool,
    pub policy_source: EnforcementPolicySourcePlan,
}

impl EnforcementPlan {
    pub fn resolve(config: &AgentConfig) -> Self {
        Self {
            mode: config.enforcement.mode,
            config_selector_configured: config.enforcement.selector.is_some(),
            policy_source: EnforcementPolicySourcePlan::from_config(
                &config.enforcement.policy.source,
            ),
        }
    }
}

pub fn validate_static_runtime_config(config: &AgentConfig) -> Result<(), RuntimeError> {
    config.validate_basic()?;
    validate_static_runtime_config_fields(config)?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnforcementPolicySourcePlan {
    None,
    LocalManifest {
        source_kind: EnforcementPolicySourceKind,
        path: PathBuf,
    },
    Remote {
        endpoint: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementPolicySourceKind {
    File,
    Directory,
}

impl EnforcementPolicySourcePlan {
    fn from_config(source: &EnforcementPolicySourceConfig) -> Self {
        match source {
            EnforcementPolicySourceConfig::None => Self::None,
            EnforcementPolicySourceConfig::File { path } => Self::LocalManifest {
                source_kind: EnforcementPolicySourceKind::File,
                path: path.clone(),
            },
            EnforcementPolicySourceConfig::Directory { path } => Self::LocalManifest {
                source_kind: EnforcementPolicySourceKind::Directory,
                path: path.join("manifest.toml"),
            },
            EnforcementPolicySourceConfig::Remote { endpoint } => Self::Remote {
                endpoint: endpoint.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportPlan {
    pub worker: ExportWorkerPlan,
    pub sinks: Vec<ExportSinkPlan>,
}

impl ExportPlan {
    fn resolve(config: &AgentConfig) -> Self {
        let materials_by_id = export_tls_materials_by_id(&config.tls.materials);
        let default_sink_batches_per_tick =
            export_worker_default_sink_batches_per_tick(config.export.worker.schedule);
        let sinks = config
            .exporters
            .iter()
            .map(|exporter| ExportSinkPlan {
                id: exporter.id.clone(),
                transport: exporter.transport,
                endpoint: exporter.endpoint.clone(),
                codec: exporter.codec,
                headers: exporter.headers.clone(),
                tls: ExportSinkTlsPlan::from_config(&exporter.tls, &materials_by_id),
                worker: ExportSinkWorkerPlan::from_config(
                    exporter.worker.batches_per_tick,
                    default_sink_batches_per_tick,
                ),
            })
            .collect::<Vec<_>>();
        let worker = match (config.export.worker.enabled, sinks.is_empty()) {
            (false, _) => ExportWorkerPlan::Disabled {
                reason: "export worker disabled by config".to_string(),
            },
            (true, true) => ExportWorkerPlan::Disabled {
                reason: "export worker has no planned sinks".to_string(),
            },
            (true, false) => ExportWorkerPlan::from(config.export.worker.schedule),
        };

        Self { worker, sinks }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ExportWorkerPlan {
    Disabled {
        reason: String,
    },
    FixedIntervalBounded {
        interval_ms: u64,
        batches_per_sink_per_tick: u64,
        sink_timeout_ms: u64,
        failure_backoff_ms: u64,
    },
}

impl ExportWorkerPlan {
    pub fn disabled_reason(&self) -> Option<&str> {
        match self {
            Self::Disabled { reason } => Some(reason),
            Self::FixedIntervalBounded { .. } => None,
        }
    }
}

impl From<ExportWorkerScheduleConfig> for ExportWorkerPlan {
    fn from(value: ExportWorkerScheduleConfig) -> Self {
        match value {
            ExportWorkerScheduleConfig::FixedIntervalBounded {
                interval_ms,
                batches_per_sink_per_tick,
                sink_timeout_ms,
                failure_backoff_ms,
            } => Self::FixedIntervalBounded {
                interval_ms,
                batches_per_sink_per_tick,
                sink_timeout_ms,
                failure_backoff_ms,
            },
        }
    }
}

fn export_worker_default_sink_batches_per_tick(schedule: ExportWorkerScheduleConfig) -> u64 {
    match schedule {
        ExportWorkerScheduleConfig::FixedIntervalBounded {
            batches_per_sink_per_tick,
            ..
        } => batches_per_sink_per_tick.max(1),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSinkPlan {
    pub id: String,
    pub transport: ExporterTransport,
    pub endpoint: String,
    pub codec: CompressionCodecName,
    pub headers: BTreeMap<String, String>,
    pub tls: ExportSinkTlsPlan,
    pub worker: ExportSinkWorkerPlan,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSinkWorkerPlan {
    pub batches_per_tick_override: Option<u64>,
    pub effective_batches_per_tick: NonZeroU64,
}

impl ExportSinkWorkerPlan {
    fn from_config(batches_per_tick_override: Option<u64>, default_batches_per_tick: u64) -> Self {
        let sanitized_override =
            batches_per_tick_override.filter(|batches_per_tick| *batches_per_tick > 0);
        let effective_batches_per_tick =
            NonZeroU64::new(sanitized_override.unwrap_or(default_batches_per_tick))
                .unwrap_or(NonZeroU64::MIN);
        Self {
            batches_per_tick_override: sanitized_override,
            effective_batches_per_tick,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportSinkTlsPlan {
    pub trust_anchors: Vec<ExportTlsMaterialPlan>,
    pub client_certificates: Vec<ExportTlsMaterialPlan>,
    pub client_private_key: Option<ExportTlsMaterialPlan>,
}

impl ExportSinkTlsPlan {
    fn from_config(
        config: &ExporterTlsConfig,
        materials_by_id: &BTreeMap<&str, ExportTlsMaterialPlan>,
    ) -> Self {
        Self {
            trust_anchors: config
                .trust_anchor_refs
                .iter()
                .filter_map(|reference| materials_by_id.get(reference.as_str()))
                .cloned()
                .collect(),
            client_certificates: config
                .client_certificate_refs
                .iter()
                .filter_map(|reference| materials_by_id.get(reference.as_str()))
                .cloned()
                .collect(),
            client_private_key: config
                .client_private_key_ref
                .as_deref()
                .and_then(|reference| materials_by_id.get(reference))
                .cloned(),
        }
    }
}

fn export_tls_materials_by_id(
    materials: &[TlsMaterialConfig],
) -> BTreeMap<&str, ExportTlsMaterialPlan> {
    tls_materials_by_id(materials, is_export_tls_material)
}

fn tls_plaintext_materials_by_id(
    materials: &[TlsMaterialConfig],
) -> BTreeMap<&str, TlsPlaintextMaterialPlan> {
    tls_materials_by_id(materials, is_plaintext_tls_material)
}

fn tls_materials_by_id(
    materials: &[TlsMaterialConfig],
    include: impl Fn(TlsMaterialKind) -> bool,
) -> BTreeMap<&str, TlsMaterialPlan> {
    materials
        .iter()
        .filter_map(|material| {
            let id = material.id.as_deref()?;
            include(material.kind).then(|| {
                (
                    id,
                    TlsMaterialPlan {
                        id: id.to_string(),
                        kind: material.kind,
                        path: material.path.clone(),
                    },
                )
            })
        })
        .collect()
}

fn is_export_tls_material(kind: TlsMaterialKind) -> bool {
    matches!(
        kind,
        TlsMaterialKind::TrustAnchor
            | TlsMaterialKind::ClientCertificate
            | TlsMaterialKind::ClientPrivateKey
    )
}

fn is_plaintext_tls_material(kind: TlsMaterialKind) -> bool {
    matches!(
        kind,
        TlsMaterialKind::KeyLogFile | TlsMaterialKind::SessionSecretFile
    )
}

fn tls_plaintext_materials_from_refs(
    refs: &[String],
    expected_kind: TlsMaterialKind,
    materials_by_id: &BTreeMap<&str, TlsPlaintextMaterialPlan>,
) -> Vec<TlsPlaintextMaterialPlan> {
    refs.iter()
        .filter_map(|reference| materials_by_id.get(reference.as_str()))
        .filter(|material| material.kind == expected_kind)
        .cloned()
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturePlan {
    pub selection: CaptureSelection,
    pub fallback_backends: Vec<LiveCaptureBackend>,
    pub selected_backend: Option<CaptureBackend>,
    pub selected_provider: Option<CaptureProviderDescriptor>,
    pub mode: CapturePlanMode,
    pub candidates: Vec<CaptureProviderDescriptor>,
    pub reason: Option<String>,
}

impl CapturePlan {
    fn resolve(config: &AgentConfig, registry: &ProviderRegistry) -> Self {
        let candidates = capture_candidates(config)
            .into_iter()
            .map(|backend| registry.capture_provider(backend))
            .collect::<Vec<_>>();

        let selected_provider = candidates
            .iter()
            .find(|candidate| {
                candidate.selectable()
                    && match config.capture.selection {
                        CaptureSelection::Replay => candidate.backend == CaptureBackend::Replay,
                        CaptureSelection::PlaintextFeed => {
                            candidate.backend == CaptureBackend::PlaintextFeed
                        }
                        CaptureSelection::Auto
                        | CaptureSelection::Ebpf
                        | CaptureSelection::Libpcap => candidate.live(),
                    }
            })
            .cloned();
        let selected_backend = selected_provider.as_ref().map(|provider| provider.backend);
        let mode = selected_provider
            .as_ref()
            .map_or(CapturePlanMode::Unavailable, |provider| {
                if provider.live() {
                    CapturePlanMode::Live
                } else if provider.plaintext_feed() {
                    CapturePlanMode::PlaintextFeed
                } else {
                    CapturePlanMode::Replay
                }
            });
        let reason = selected_backend
            .is_none()
            .then(|| match config.capture.selection {
                CaptureSelection::Replay => {
                    "replay capture provider is not available in this build/runtime".to_string()
                }
                CaptureSelection::PlaintextFeed => {
                    "plaintext feed capture provider is not available in this build/runtime"
                        .to_string()
                }
                CaptureSelection::Auto | CaptureSelection::Ebpf | CaptureSelection::Libpcap => {
                    "no live capture provider is available in this build/runtime".to_string()
                }
            });

        Self {
            selection: config.capture.selection,
            fallback_backends: config.capture.fallback_backends.clone(),
            selected_backend,
            selected_provider,
            mode,
            candidates,
            reason,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapturePlanMode {
    Live,
    PlaintextFeed,
    Replay,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureProviderDescriptor {
    pub backend: CaptureBackend,
    pub builder: CaptureProviderBuilder,
    pub mode: RuntimeMode,
    pub reason: Option<String>,
}

impl CaptureProviderDescriptor {
    pub fn available(backend: CaptureBackend, builder: CaptureProviderBuilder) -> Self {
        Self {
            backend,
            builder,
            mode: RuntimeMode::Available,
            reason: None,
        }
    }

    pub fn degraded(
        backend: CaptureBackend,
        builder: CaptureProviderBuilder,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            builder,
            mode: RuntimeMode::Degraded,
            reason: Some(reason.into()),
        }
    }

    pub fn unavailable(
        backend: CaptureBackend,
        builder: CaptureProviderBuilder,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            backend,
            builder,
            mode: RuntimeMode::Unavailable,
            reason: Some(reason.into()),
        }
    }

    pub fn capability(&self) -> CapabilityKind {
        capture_backend_capability(self.backend)
    }

    pub fn live(&self) -> bool {
        matches!(self.backend, CaptureBackend::Ebpf | CaptureBackend::Libpcap)
    }

    pub fn plaintext_feed(&self) -> bool {
        self.backend == CaptureBackend::PlaintextFeed
    }

    pub fn state(&self) -> CapabilityState {
        match self.mode {
            RuntimeMode::Available => CapabilityState::available(self.capability()),
            RuntimeMode::Degraded => CapabilityState::degraded(
                self.capability(),
                self.reason
                    .as_deref()
                    .unwrap_or("capture provider is degraded"),
            ),
            RuntimeMode::Unavailable => CapabilityState::unavailable(
                self.capability(),
                self.reason
                    .as_deref()
                    .unwrap_or("capture provider is unavailable"),
            ),
        }
    }

    fn selectable(&self) -> bool {
        self.mode == RuntimeMode::Available && self.builder.supports(self.backend)
    }

    fn unselectable_reason(&self) -> String {
        self.reason.clone().unwrap_or_else(|| {
            format!(
                "{:?} capture provider is not available in this build/runtime",
                self.backend
            )
        })
    }

    fn normalized(mut self) -> Self {
        if self.mode != RuntimeMode::Unavailable && !self.builder.supports(self.backend) {
            self.mode = RuntimeMode::Unavailable;
            self.reason = Some(format!(
                "{:?} builder cannot construct {:?} capture provider",
                self.builder, self.backend
            ));
        }
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureProviderBuilder {
    Replay,
    Ebpf,
    Libpcap,
    PlaintextFeed,
    Unimplemented,
}

impl CaptureProviderBuilder {
    fn supports(self, backend: CaptureBackend) -> bool {
        matches!(
            (self, backend),
            (Self::Replay, CaptureBackend::Replay)
                | (Self::Ebpf, CaptureBackend::Ebpf)
                | (Self::Libpcap, CaptureBackend::Libpcap)
                | (Self::PlaintextFeed, CaptureBackend::PlaintextFeed)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRegistry {
    capture_providers: Vec<CaptureProviderDescriptor>,
    platform_capabilities: Vec<CapabilityState>,
}

impl ProviderRegistry {
    pub fn with_default_platform(capture_providers: Vec<CaptureProviderDescriptor>) -> Self {
        let procfs = ProcfsAttributor::new();
        let procfs_socket = ProcfsSocketResolver::new();
        Self::new(
            capture_providers,
            default_platform_capabilities(procfs)
                .into_iter()
                .chain(procfs_socket.capabilities())
                .collect(),
        )
    }

    pub fn new(
        capture_providers: Vec<CaptureProviderDescriptor>,
        platform_capabilities: Vec<CapabilityState>,
    ) -> Self {
        Self {
            capture_providers: capture_providers
                .into_iter()
                .map(CaptureProviderDescriptor::normalized)
                .collect(),
            platform_capabilities,
        }
    }

    pub fn capability_matrix(&self) -> CapabilityMatrix {
        CapabilityMatrix::new(
            self.capture_providers
                .iter()
                .map(CaptureProviderDescriptor::state)
                .chain(self.platform_capabilities.iter().cloned()),
        )
    }

    pub fn capture_provider(&self, backend: CaptureBackend) -> CaptureProviderDescriptor {
        self.capture_providers
            .iter()
            .find(|candidate| candidate.backend == backend)
            .cloned()
            .unwrap_or_else(|| {
                CaptureProviderDescriptor::unavailable(
                    backend,
                    CaptureProviderBuilder::Unimplemented,
                    "capture backend is not registered",
                )
            })
    }
}

fn validate_runtime_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
) -> Result<(), ConfigValidationError> {
    let mut violations = Vec::new();
    collect_static_runtime_config_violations(config, &mut violations);
    validate_capture_config(config, registry, &mut violations);
    validate_registry_tls_config(config, registry, &mut violations);
    validate_registry_enforcement_config(config, registry, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError::new(violations))
    }
}

fn validate_static_runtime_config_fields(
    config: &AgentConfig,
) -> Result<(), ConfigValidationError> {
    let mut violations = Vec::new();
    collect_static_runtime_config_violations(config, &mut violations);
    if violations.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError::new(violations))
    }
}

fn collect_static_runtime_config_violations(
    config: &AgentConfig,
    violations: &mut Vec<ConfigViolation>,
) {
    validate_static_tls_config(config, violations);
    validate_policy_config(config, violations);
    validate_static_enforcement_config(config, violations);
    validate_exporters(config, violations);
}

fn validate_policy_config(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
    for policy in config.policies.iter().filter(|policy| policy.enabled) {
        if let Some(selector) = &policy.selector
            && let Err(error) = selector.compile()
        {
            violations.push(ConfigViolation {
                field: format!("policies.{}.selector", policy.id),
                reason: error.to_string(),
            });
        }
    }
}

fn validate_capture_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    let Some(backend) = config.capture.selection.explicit_backend() else {
        return;
    };
    let provider = registry.capture_provider(backend);
    if !provider.selectable() {
        violations.push(ConfigViolation {
            field: "capture.selection".to_string(),
            reason: provider.unselectable_reason(),
        });
    }
}

fn validate_static_tls_config(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
    if let Some(selector) = &config.tls.plaintext.selector
        && let Err(error) = selector.compile()
    {
        violations.push(ConfigViolation {
            field: "tls.plaintext.selector".to_string(),
            reason: error.to_string(),
        });
    }
    if !config.tls.plaintext.enabled {
        return;
    }
    if matches!(config.tls.plaintext.provider, TlsPlaintextProvider::Keylog) {
        violations.push(ConfigViolation {
            field: "tls.plaintext.provider".to_string(),
            reason: format!(
                "{:?} plaintext provider is reserved but not implemented",
                config.tls.plaintext.provider
            ),
        });
    }
}

fn validate_registry_tls_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    if !config.tls.plaintext.enabled {
        return;
    }
    match config.tls.plaintext.provider {
        TlsPlaintextProvider::LibsslUprobe => require_available(
            &registry.capability_matrix(),
            CapabilityKind::LibsslUprobe,
            "tls.plaintext.enabled",
            "libssl uprobe plaintext provider is not available in this build/runtime",
            violations,
        ),
        TlsPlaintextProvider::Keylog => {}
    }
}

fn validate_static_enforcement_config(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
    if let Some(selector) = &config.enforcement.selector
        && let Err(error) = selector.compile()
    {
        violations.push(ConfigViolation {
            field: "enforcement.selector".to_string(),
            reason: error.to_string(),
        });
    }
    if config.enforcement.mode == EnforcementMode::Enforce {
        violations.push(ConfigViolation {
            field: "enforcement.mode".to_string(),
            reason: "real enforcement is not implemented in this build/runtime".to_string(),
        });
    }
}

fn validate_registry_enforcement_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    match config.enforcement.mode {
        EnforcementMode::Disabled | EnforcementMode::AuditOnly | EnforcementMode::Enforce => {}
        EnforcementMode::DryRun => require_available(
            &registry.capability_matrix(),
            CapabilityKind::DryRunEnforcement,
            "enforcement.mode",
            "dry-run enforcement provider is not available in this build/runtime",
            violations,
        ),
    }
}

fn validate_exporters(config: &AgentConfig, violations: &mut Vec<ConfigViolation>) {
    for exporter in &config.exporters {
        match exporter.transport {
            ExporterTransport::Webhook => {}
            ExporterTransport::Grpc | ExporterTransport::Kafka | ExporterTransport::Otlp => {
                violations.push(ConfigViolation {
                    field: format!("exporters.{}.transport", exporter.id),
                    reason: format!(
                        "{:?} exporter is reserved but not implemented",
                        exporter.transport
                    ),
                });
            }
        }
    }
}

fn require_available(
    capabilities: &CapabilityMatrix,
    capability: CapabilityKind,
    field: impl Into<String>,
    reason: impl Into<String>,
    violations: &mut Vec<ConfigViolation>,
) {
    if capabilities.mode(capability) != RuntimeMode::Available {
        violations.push(ConfigViolation {
            field: field.into(),
            reason: reason.into(),
        });
    }
}

fn capture_candidates(config: &AgentConfig) -> Vec<CaptureBackend> {
    match config.capture.selection.explicit_backend() {
        None => config
            .capture
            .fallback_backends
            .iter()
            .copied()
            .map(CaptureBackend::from)
            .collect(),
        Some(backend) => vec![backend],
    }
}

fn default_platform_capabilities(
    procfs: impl ProcessAttributor,
) -> impl IntoIterator<Item = CapabilityState> {
    [
        CapabilityState::unavailable(
            CapabilityKind::LibsslUprobe,
            "libssl uprobe attach candidate discovery code exists, but it is not wired into runtime and the uprobe loader and plaintext event provider are not implemented in this build",
        ),
        CapabilityState::available(CapabilityKind::Http1),
        CapabilityState::available(CapabilityKind::Sse),
        CapabilityState::available(CapabilityKind::WebSocketHandoff),
        CapabilityState::degraded(
            CapabilityKind::LuaJit,
            "policy runtime is wired into replay and live capture, but hot reload and multiple active bundles are not implemented",
        ),
        CapabilityState::degraded(
            CapabilityKind::DurableSpool,
            "ingress and export lanes exist, but parser recovery from ingress journal is not implemented",
        ),
        CapabilityState::degraded(
            CapabilityKind::IngressJournal,
            "durable ingress lane is wired into replay, but parser recovery is not implemented",
        ),
        CapabilityState::available(CapabilityKind::ExportQueue),
        CapabilityState::degraded(
            CapabilityKind::WebhookExporter,
            "webhook transport can drain planned export sinks with configured fixed worker bounds, per-sink batch quota, and fixed failure backoff during run and replay CLI webhook output during replay, but adaptive/exponential backoff and retention deadline are not implemented",
        ),
        CapabilityState::available(
            CapabilityKind::DryRunEnforcement,
        ),
    ]
    .into_iter()
    .chain(procfs.capabilities())
}

fn capture_backend_capability(backend: CaptureBackend) -> CapabilityKind {
    match backend {
        CaptureBackend::Ebpf => CapabilityKind::Ebpf,
        CaptureBackend::Libpcap => CapabilityKind::Libpcap,
        CaptureBackend::PlaintextFeed => CapabilityKind::ExternalPlaintextFeed,
        CaptureBackend::Replay => CapabilityKind::ReplayCapture,
    }
}

#[cfg(test)]
mod tests;
