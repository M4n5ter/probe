use probe_config::{AgentConfig, CaptureBackend, CaptureSelection, LiveCaptureBackend};
use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};
use serde::{Deserialize, Serialize};

use super::registry::ProviderRegistry;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturePlan {
    pub selection: CaptureSelection,
    pub fallback_backends: Vec<LiveCaptureBackend>,
    pub selected_backend: Option<CaptureBackend>,
    pub selected_provider: Option<CaptureProviderDescriptor>,
    pub selected_provider_runtime_mode: Option<RuntimeMode>,
    pub selected_evidence_mode: Option<CaptureEvidenceMode>,
    pub evidence_reason: Option<String>,
    pub mode: CapturePlanMode,
    pub candidates: Vec<CaptureProviderDescriptor>,
    pub reason: Option<String>,
}

impl CapturePlan {
    pub(super) fn resolve(config: &AgentConfig, registry: &ProviderRegistry) -> Self {
        let candidates = capture_candidates(config)
            .into_iter()
            .map(|backend| registry.capture_provider(backend))
            .collect::<Vec<_>>();

        let selected_provider = candidates
            .iter()
            .find(|candidate| candidate.openable())
            .cloned();
        let selected_backend = selected_provider.as_ref().map(|provider| provider.backend);
        let mode = selected_provider
            .as_ref()
            .map_or(CapturePlanMode::Unavailable, |provider| {
                provider.plan_mode()
            });
        let reason = capture_plan_reason(config.capture.selection, selected_backend);

        Self {
            selection: config.capture.selection,
            fallback_backends: config.capture.fallback_backends.clone(),
            selected_backend,
            selected_provider_runtime_mode: selected_provider
                .as_ref()
                .map(|provider| provider.runtime_mode),
            selected_evidence_mode: selected_provider
                .as_ref()
                .map(|provider| provider.evidence_mode),
            evidence_reason: selected_provider
                .as_ref()
                .and_then(|provider| provider.evidence_reason.clone()),
            selected_provider,
            mode,
            candidates,
            reason,
        }
    }

    pub fn live_provider_open_candidates(&self) -> Vec<CaptureProviderDescriptor> {
        match self.selection {
            CaptureSelection::Auto => self
                .candidates
                .iter()
                .filter(|candidate| candidate.live() && candidate.openable())
                .cloned()
                .collect(),
            CaptureSelection::Ebpf | CaptureSelection::Libpcap => {
                self.selected_provider.iter().cloned().collect()
            }
            CaptureSelection::PlaintextFeed
            | CaptureSelection::CaptureEventFeed
            | CaptureSelection::Replay => Vec::new(),
        }
    }
}

fn capture_plan_reason(
    selection: CaptureSelection,
    selected_backend: Option<CaptureBackend>,
) -> Option<String> {
    selected_backend
        .is_none()
        .then(|| unavailable_capture_reason(selection))
}

fn unavailable_capture_reason(selection: CaptureSelection) -> String {
    match selection {
        CaptureSelection::Replay => {
            "replay capture provider is not available in this build/runtime".to_string()
        }
        CaptureSelection::PlaintextFeed => {
            "plaintext feed capture provider is not available in this build/runtime".to_string()
        }
        CaptureSelection::CaptureEventFeed => {
            "capture event feed provider is not available in this build/runtime".to_string()
        }
        CaptureSelection::Auto | CaptureSelection::Ebpf | CaptureSelection::Libpcap => {
            "no live capture provider is available in this build/runtime".to_string()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapturePlanMode {
    Live,
    PlaintextFeed,
    CaptureEventFeed,
    Replay,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureEvidenceMode {
    Nominal,
    BestEffort,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureProviderDescriptor {
    pub backend: CaptureBackend,
    pub builder: CaptureProviderBuilder,
    pub runtime_mode: RuntimeMode,
    pub capability_mode: RuntimeMode,
    pub evidence_mode: CaptureEvidenceMode,
    pub evidence_reason: Option<String>,
    pub reason: Option<String>,
}

impl CaptureProviderDescriptor {
    pub fn available(backend: CaptureBackend, builder: CaptureProviderBuilder) -> Self {
        Self {
            backend,
            builder,
            runtime_mode: RuntimeMode::Available,
            capability_mode: RuntimeMode::Available,
            evidence_mode: CaptureEvidenceMode::Nominal,
            evidence_reason: None,
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
            runtime_mode: RuntimeMode::Available,
            capability_mode: RuntimeMode::Degraded,
            evidence_mode: CaptureEvidenceMode::BestEffort,
            evidence_reason: Some(reason.into()),
            reason: None,
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
            runtime_mode: RuntimeMode::Unavailable,
            capability_mode: RuntimeMode::Unavailable,
            evidence_mode: CaptureEvidenceMode::Nominal,
            evidence_reason: None,
            reason: Some(reason.into()),
        }
    }

    pub fn with_best_effort_evidence(mut self, reason: impl Into<String>) -> Self {
        self.evidence_mode = CaptureEvidenceMode::BestEffort;
        self.evidence_reason = Some(reason.into());
        self
    }

    pub fn capability(&self) -> CapabilityKind {
        capture_backend_capability(self.backend)
    }

    pub fn live(&self) -> bool {
        matches!(self.backend, CaptureBackend::Ebpf | CaptureBackend::Libpcap)
    }

    pub fn plan_mode(&self) -> CapturePlanMode {
        capture_backend_plan_mode(self.backend)
    }

    pub fn state(&self) -> CapabilityState {
        match self.capability_mode {
            RuntimeMode::Available => CapabilityState::available(self.capability()),
            RuntimeMode::Degraded => CapabilityState::degraded(
                self.capability(),
                self.evidence_reason
                    .as_deref()
                    .or(self.reason.as_deref())
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

    pub(super) fn openable(&self) -> bool {
        self.builder.supports(self.backend) && self.runtime_mode != RuntimeMode::Unavailable
    }

    pub(super) fn unselectable_reason(&self) -> String {
        self.reason
            .clone()
            .or_else(|| self.evidence_reason.clone())
            .unwrap_or_else(|| {
                format!(
                    "{:?} capture provider is not available in this build/runtime",
                    self.backend
                )
            })
    }

    pub(super) fn normalized(mut self) -> Self {
        if self.capability_mode != RuntimeMode::Unavailable && !self.builder.supports(self.backend)
        {
            self.runtime_mode = RuntimeMode::Unavailable;
            self.capability_mode = RuntimeMode::Unavailable;
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
    CaptureEventFeed,
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
                | (Self::CaptureEventFeed, CaptureBackend::CaptureEventFeed)
        )
    }
}

fn capture_candidates(config: &AgentConfig) -> Vec<CaptureBackend> {
    config.capture.candidate_backends()
}

fn capture_backend_capability(backend: CaptureBackend) -> CapabilityKind {
    match backend {
        CaptureBackend::Ebpf => CapabilityKind::Ebpf,
        CaptureBackend::Libpcap => CapabilityKind::Libpcap,
        CaptureBackend::PlaintextFeed => CapabilityKind::ExternalPlaintextFeed,
        CaptureBackend::CaptureEventFeed => CapabilityKind::CaptureEventFeed,
        CaptureBackend::Replay => CapabilityKind::ReplayCapture,
    }
}

fn capture_backend_plan_mode(backend: CaptureBackend) -> CapturePlanMode {
    match backend {
        CaptureBackend::Ebpf | CaptureBackend::Libpcap => CapturePlanMode::Live,
        CaptureBackend::PlaintextFeed => CapturePlanMode::PlaintextFeed,
        CaptureBackend::CaptureEventFeed => CapturePlanMode::CaptureEventFeed,
        CaptureBackend::Replay => CapturePlanMode::Replay,
    }
}

#[cfg(test)]
mod tests {
    use probe_config::{AgentConfig, CaptureBackend, CaptureSelection};
    use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};

    use crate::plan::registry::ProviderRegistry;

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

        let config = AgentConfig::default();
        let plan = CapturePlan::resolve(&config, &registry);

        assert_eq!(plan.mode, CapturePlanMode::Unavailable);
        assert_eq!(plan.selected_backend, None);
        assert!(
            plan.reason
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
                CaptureProviderDescriptor::unavailable(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Unimplemented,
                    "eBPF host probe: bpffs path /sys/fs/bpf does not exist",
                ),
                capture_provider(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                    RuntimeMode::Available,
                ),
            ],
            test_platform_capabilities(),
        );

        let config = AgentConfig::default();
        let plan = CapturePlan::resolve(&config, &registry);

        assert_eq!(plan.mode, CapturePlanMode::Live);
        assert_eq!(plan.selected_backend, Some(CaptureBackend::Libpcap));
        assert_eq!(
            plan.selected_provider
                .as_ref()
                .map(|provider| provider.builder),
            Some(CaptureProviderBuilder::Libpcap)
        );
        Ok(())
    }

    #[test]
    fn auto_selection_prefers_degraded_ebpf_before_available_libpcap()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![
                CaptureProviderDescriptor::degraded(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Ebpf,
                    "eBPF observation provider does not capture payload",
                ),
                capture_provider(
                    CaptureBackend::Libpcap,
                    CaptureProviderBuilder::Libpcap,
                    RuntimeMode::Available,
                ),
            ],
            test_platform_capabilities(),
        );

        let config = AgentConfig::default();
        let plan = CapturePlan::resolve(&config, &registry);

        assert_eq!(plan.mode, CapturePlanMode::Live);
        assert_eq!(plan.selected_backend, Some(CaptureBackend::Ebpf));
        assert_eq!(
            plan.selected_provider_runtime_mode,
            Some(RuntimeMode::Available)
        );
        assert_eq!(
            plan.selected_evidence_mode,
            Some(CaptureEvidenceMode::BestEffort)
        );
        assert_eq!(
            plan.selected_provider
                .as_ref()
                .map(|provider| provider.capability_mode),
            Some(RuntimeMode::Degraded)
        );
        assert!(
            plan.evidence_reason
                .as_deref()
                .is_some_and(|reason| reason.contains("does not capture payload"))
        );
        assert_eq!(plan.reason, None);
        Ok(())
    }

    #[test]
    fn available_provider_can_expose_best_effort_evidence_without_degrading_capability() {
        let descriptor = CaptureProviderDescriptor::available(
            CaptureBackend::Libpcap,
            CaptureProviderBuilder::Libpcap,
        )
        .with_best_effort_evidence("bounded stream assembly is best-effort");

        assert_eq!(descriptor.capability_mode, RuntimeMode::Available);
        assert_eq!(descriptor.runtime_mode, RuntimeMode::Available);
        assert_eq!(descriptor.evidence_mode, CaptureEvidenceMode::BestEffort);
        assert_eq!(
            descriptor.evidence_reason.as_deref(),
            Some("bounded stream assembly is best-effort")
        );
        assert_eq!(
            descriptor.state(),
            CapabilityState::available(CapabilityKind::Libpcap)
        );
    }

    #[test]
    fn explicit_degraded_provider_is_selectable_by_runtime_availability()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![CaptureProviderDescriptor::degraded(
                CaptureBackend::Ebpf,
                CaptureProviderBuilder::Ebpf,
                "eBPF observation provider does not capture payload",
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;

        let plan = CapturePlan::resolve(&config, &registry);

        assert_eq!(plan.mode, CapturePlanMode::Live);
        assert_eq!(plan.selected_backend, Some(CaptureBackend::Ebpf));
        assert_eq!(
            plan.selected_provider_runtime_mode,
            Some(RuntimeMode::Available)
        );
        assert_eq!(
            plan.selected_evidence_mode,
            Some(CaptureEvidenceMode::BestEffort)
        );
        assert_eq!(
            plan.selected_provider
                .as_ref()
                .map(|provider| provider.capability_mode),
            Some(RuntimeMode::Degraded)
        );
        Ok(())
    }

    #[test]
    fn external_plaintext_feed_resolves_to_feed_mode() -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::PlaintextFeed,
                CaptureProviderBuilder::PlaintextFeed,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::PlaintextFeed;
        config.capture.plaintext_feed.path = Some("/tmp/feed.jsonl".into());

        let plan = CapturePlan::resolve(&config, &registry);

        assert_eq!(plan.mode, CapturePlanMode::PlaintextFeed);
        assert_eq!(plan.selected_backend, Some(CaptureBackend::PlaintextFeed));
        Ok(())
    }

    #[test]
    fn capture_event_feed_resolves_to_feed_mode() -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::CaptureEventFeed,
                CaptureProviderBuilder::CaptureEventFeed,
                RuntimeMode::Available,
            )],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::CaptureEventFeed;
        config.capture.capture_event_feed.path = Some("/tmp/capture-events.jsonl".into());

        let plan = CapturePlan::resolve(&config, &registry);

        assert_eq!(plan.mode, CapturePlanMode::CaptureEventFeed);
        assert_eq!(
            plan.selected_backend,
            Some(CaptureBackend::CaptureEventFeed)
        );
        Ok(())
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

        let plan = CapturePlan::resolve(&config, &registry);

        assert_eq!(plan.mode, CapturePlanMode::Replay);
        assert_eq!(plan.selected_backend, Some(CaptureBackend::Replay));
        assert_eq!(
            plan.selected_provider
                .as_ref()
                .map(|provider| provider.builder),
            Some(CaptureProviderBuilder::Replay)
        );
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
            CapabilityState::available(CapabilityKind::WebSocketFrame),
            CapabilityState::unavailable(CapabilityKind::LibsslUprobe, "not built"),
            CapabilityState::available(CapabilityKind::DryRunEnforcement),
            CapabilityState::unavailable(CapabilityKind::ConnectionEnforcement, "not built"),
        ]
    }
}
