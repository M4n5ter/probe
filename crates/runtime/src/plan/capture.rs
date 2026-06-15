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
            .find(|candidate| {
                candidate.selectable_for(config.capture.selection)
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
    pub selection_policy: CaptureProviderSelectionPolicy,
    pub reason: Option<String>,
}

impl CaptureProviderDescriptor {
    pub fn available(backend: CaptureBackend, builder: CaptureProviderBuilder) -> Self {
        Self {
            backend,
            builder,
            mode: RuntimeMode::Available,
            selection_policy: CaptureProviderSelectionPolicy::AvailableOnly,
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
            selection_policy: CaptureProviderSelectionPolicy::AvailableOnly,
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
            selection_policy: CaptureProviderSelectionPolicy::AvailableOnly,
            reason: Some(reason.into()),
        }
    }

    pub fn allow_explicit_degraded(mut self) -> Self {
        self.selection_policy = CaptureProviderSelectionPolicy::AllowExplicitDegraded;
        self
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

    pub(super) fn selectable_for(&self, selection: CaptureSelection) -> bool {
        if !self.builder.supports(self.backend) {
            return false;
        }
        match selection {
            CaptureSelection::Auto => self.selection_policy.auto_selectable(self.mode),
            CaptureSelection::Ebpf
            | CaptureSelection::Libpcap
            | CaptureSelection::PlaintextFeed
            | CaptureSelection::Replay => self.selection_policy.explicit_selectable(self.mode),
        }
    }

    pub(super) fn unselectable_reason(&self) -> String {
        self.reason.clone().unwrap_or_else(|| {
            format!(
                "{:?} capture provider is not available in this build/runtime",
                self.backend
            )
        })
    }

    pub(super) fn normalized(mut self) -> Self {
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
pub enum CaptureProviderSelectionPolicy {
    AvailableOnly,
    AllowExplicitDegraded,
}

impl CaptureProviderSelectionPolicy {
    fn auto_selectable(self, mode: RuntimeMode) -> bool {
        mode == RuntimeMode::Available
    }

    fn explicit_selectable(self, mode: RuntimeMode) -> bool {
        match self {
            Self::AvailableOnly => mode == RuntimeMode::Available,
            Self::AllowExplicitDegraded => mode != RuntimeMode::Unavailable,
        }
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

fn capture_backend_capability(backend: CaptureBackend) -> CapabilityKind {
    match backend {
        CaptureBackend::Ebpf => CapabilityKind::Ebpf,
        CaptureBackend::Libpcap => CapabilityKind::Libpcap,
        CaptureBackend::PlaintextFeed => CapabilityKind::ExternalPlaintextFeed,
        CaptureBackend::Replay => CapabilityKind::ReplayCapture,
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
    fn auto_selection_skips_degraded_ebpf_and_uses_available_libpcap()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![
                CaptureProviderDescriptor::degraded(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Ebpf,
                    "eBPF observation provider does not capture payload",
                )
                .allow_explicit_degraded(),
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
        Ok(())
    }

    #[test]
    fn explicit_degraded_provider_with_selection_policy_is_selectable()
    -> Result<(), Box<dyn std::error::Error>> {
        let registry = ProviderRegistry::new(
            vec![
                CaptureProviderDescriptor::degraded(
                    CaptureBackend::Ebpf,
                    CaptureProviderBuilder::Ebpf,
                    "eBPF observation provider does not capture payload",
                )
                .allow_explicit_degraded(),
            ],
            test_platform_capabilities(),
        );
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Ebpf;

        let plan = CapturePlan::resolve(&config, &registry);

        assert_eq!(plan.mode, CapturePlanMode::Live);
        assert_eq!(plan.selected_backend, Some(CaptureBackend::Ebpf));
        assert_eq!(
            plan.selected_provider
                .as_ref()
                .map(|provider| provider.mode),
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
