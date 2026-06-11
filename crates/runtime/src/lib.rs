use attribution::{ProcessAttributor, ProcfsAttributor, ProcfsSocketResolver};
use probe_config::{
    AgentConfig, CaptureBackend, CaptureSelection, ConfigError, ConfigValidationError,
    ConfigViolation, ExporterTransport, LiveCaptureBackend, TlsPlaintextProvider,
};
use probe_core::{CapabilityKind, CapabilityMatrix, CapabilityState, EnforcementMode, RuntimeMode};
use serde::{Deserialize, Serialize};
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
}

impl RuntimePlan {
    pub fn build(config: AgentConfig, registry: &ProviderRegistry) -> Result<Self, RuntimeError> {
        config.validate_basic()?;
        validate_runtime_config(&config, registry)?;
        let capabilities = registry.capability_matrix();
        let capture = CapturePlan::resolve(&config, registry);
        Ok(Self {
            config,
            capabilities,
            capture,
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
    Unimplemented,
}

impl CaptureProviderBuilder {
    fn supports(self, backend: CaptureBackend) -> bool {
        matches!(
            (self, backend),
            (Self::Replay, CaptureBackend::Replay)
                | (Self::Ebpf, CaptureBackend::Ebpf)
                | (Self::Libpcap, CaptureBackend::Libpcap)
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
    validate_capture_config(config, registry, &mut violations);
    validate_tls_config(config, registry, &mut violations);
    validate_enforcement_config(config, registry, &mut violations);
    validate_exporters(config, &mut violations);

    if violations.is_empty() {
        Ok(())
    } else {
        Err(ConfigValidationError::new(violations))
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
            reason: format!("{backend:?} capture provider is not available in this build/runtime"),
        });
    }
}

fn validate_tls_config(
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
        TlsPlaintextProvider::Keylog | TlsPlaintextProvider::ExternalFeed => {
            violations.push(ConfigViolation {
                field: "tls.plaintext.provider".to_string(),
                reason: format!(
                    "{:?} plaintext provider is reserved but not implemented",
                    config.tls.plaintext.provider
                ),
            });
        }
    }
}

fn validate_enforcement_config(
    config: &AgentConfig,
    registry: &ProviderRegistry,
    violations: &mut Vec<ConfigViolation>,
) {
    if let Some(selector) = &config.enforcement.selector
        && let Err(error) = selector.compile()
    {
        violations.push(ConfigViolation {
            field: "enforcement.selector".to_string(),
            reason: error.to_string(),
        });
    }
    match config.enforcement.mode {
        EnforcementMode::Disabled | EnforcementMode::AuditOnly => {}
        EnforcementMode::DryRun => require_available(
            &registry.capability_matrix(),
            CapabilityKind::DryRunEnforcement,
            "enforcement.mode",
            "dry-run enforcement provider is not available in this build/runtime",
            violations,
        ),
        EnforcementMode::Enforce => violations.push(ConfigViolation {
            field: "enforcement.mode".to_string(),
            reason: "real enforcement is not implemented in this build/runtime".to_string(),
        }),
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
            "TLS plaintext probe provider not implemented in this build",
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
            "webhook transport is wired into replay but not live capture",
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
        CaptureBackend::Replay => CapabilityKind::ReplayCapture,
    }
}

#[cfg(test)]
mod tests {
    use probe_core::Selector;

    use super::*;

    #[test]
    fn default_plan_is_honest_when_live_capture_is_unavailable()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![
                capture_provider(
                    CaptureBackend::Replay,
                    CaptureProviderBuilder::Replay,
                    RuntimeMode::Available,
                ),
                capture_provider(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Unimplemented,
                    RuntimeMode::Unavailable,
                ),
                capture_provider(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Unimplemented,
                    RuntimeMode::Unavailable,
                ),
            ],
            test_platform_capabilities(),
        );

        let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

        assert_eq!(plan.capture.mode, CapturePlanMode::Unavailable);
        assert_eq!(plan.capture.selected_backend, None);
        assert!(
            plan.capture
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("no live capture provider"))
        );
        Ok(())
    }

    #[test]
    fn auto_selection_uses_first_available_live_fallback() -> Result<(), Box<dyn std::error::Error>>
    {
        let registry = ProviderRegistry::new(
            vec![
                capture_provider(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Unimplemented,
                    RuntimeMode::Unavailable,
                ),
                capture_provider(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                    RuntimeMode::Available,
                ),
            ],
            test_platform_capabilities(),
        );

        let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

        assert_eq!(plan.capture.mode, CapturePlanMode::Live);
        assert_eq!(plan.capture.selected_backend, Some(CaptureBackend::Libpcap));
        assert_eq!(
            plan.capture
                .selected_provider
                .as_ref()
                .map(|provider| provider.builder),
            Some(CaptureProviderBuilder::Libpcap)
        );
        Ok(())
    }

    #[test]
    fn explicit_unavailable_backend_does_not_fallback() {
        let registry = ProviderRegistry::new(
            vec![
                capture_provider(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Unimplemented,
                    RuntimeMode::Unavailable,
                ),
                capture_provider(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                    RuntimeMode::Available,
                ),
            ],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;

        let error =
            RuntimePlan::build(config, &registry).expect_err("explicit ebpf is unavailable");

        assert!(
            error
                .to_string()
                .contains("Ebpf capture provider is not available")
        );
    }

    #[test]
    fn available_provider_requires_matching_executable_builder() {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Ebpf,
                CaptureProviderBuilder::Unimplemented,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;

        let error =
            RuntimePlan::build(config, &registry).expect_err("unimplemented builder is not usable");

        assert!(
            error
                .to_string()
                .contains("Ebpf capture provider is not available")
        );
        assert_eq!(
            registry.capability_matrix().mode(CapabilityKind::Ebpf),
            RuntimeMode::Unavailable
        );
    }

    #[test]
    fn unsupported_security_features_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(vec![], test_platform_capabilities());
        let mut config = AgentConfig::default();
        config.tls.plaintext.enabled = true;
        config.enforcement.mode = EnforcementMode::Enforce;

        let error = RuntimePlan::build(config, &registry).expect_err("config must fail closed");

        assert!(
            error
                .to_string()
                .contains("libssl uprobe plaintext provider is not available")
        );
        assert!(
            error
                .to_string()
                .contains("real enforcement is not implemented")
        );
        Ok(())
    }

    #[test]
    fn dry_run_enforcement_is_a_supported_runtime_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.enforcement.mode = EnforcementMode::DryRun;

        let plan = RuntimePlan::build(config, &registry)?;

        assert_eq!(
            plan.capabilities.mode(CapabilityKind::DryRunEnforcement),
            RuntimeMode::Available
        );
        Ok(())
    }

    #[test]
    fn websocket_handoff_is_a_supported_runtime_capability()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::with_default_platform(vec![capture_provider(
            CaptureBackend::Replay,
            CaptureProviderBuilder::Replay,
            RuntimeMode::Available,
        )]);
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;

        let plan = RuntimePlan::build(config, &registry)?;

        assert_eq!(
            plan.capabilities.mode(CapabilityKind::WebSocketHandoff),
            RuntimeMode::Available
        );
        Ok(())
    }

    #[test]
    fn enforcement_selector_is_validated_during_plan_build() {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;
        config.enforcement.selector = Some(Selector::All {
            selectors: Vec::new(),
        });

        let error = RuntimePlan::build(config, &registry)
            .expect_err("invalid enforcement selector must fail plan build");

        assert!(error.to_string().contains("enforcement.selector"));
    }

    #[test]
    fn replay_backend_resolves_to_replay_mode() -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Replay,
                CaptureProviderBuilder::Replay,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Replay;

        let plan = RuntimePlan::build(config, &registry)?;

        assert_eq!(plan.capture.mode, CapturePlanMode::Replay);
        assert_eq!(plan.capture.selected_backend, Some(CaptureBackend::Replay));
        assert_eq!(
            plan.capture
                .selected_provider
                .as_ref()
                .map(|provider| provider.builder),
            Some(CaptureProviderBuilder::Replay)
        );
        Ok(())
    }

    #[test]
    fn run_requirement_fails_without_live_capture() -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Ebpf,
                CaptureProviderBuilder::Unimplemented,
                RuntimeMode::Unavailable,
            )],
            test_platform_capabilities(),
        );
        let plan = RuntimePlan::build(AgentConfig::default(), &registry)?;

        let error = plan
            .require_live_capture()
            .expect_err("run must fail closed");

        assert!(error.to_string().contains("no live capture provider"));
        Ok(())
    }

    fn capture_provider(
        backend: CaptureBackend,
        builder: CaptureProviderBuilder,
        mode: RuntimeMode,
    ) -> CaptureProviderDescriptor {
        match mode {
            RuntimeMode::Available => CaptureProviderDescriptor::available(backend, builder),
            RuntimeMode::Degraded => {
                CaptureProviderDescriptor::degraded(backend, builder, "degraded")
            }
            RuntimeMode::Unavailable => {
                CaptureProviderDescriptor::unavailable(backend, builder, "unavailable")
            }
        }
    }

    fn test_platform_capabilities() -> Vec<CapabilityState> {
        vec![
            CapabilityState::available(CapabilityKind::Http1),
            CapabilityState::available(CapabilityKind::Sse),
            CapabilityState::available(CapabilityKind::WebSocketHandoff),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
        ]
    }
}
