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
