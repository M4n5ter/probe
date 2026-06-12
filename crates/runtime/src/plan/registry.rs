use attribution::{ProcessAttributor, ProcfsAttributor, ProcfsSocketResolver};
use probe_config::CaptureBackend;
use probe_core::{CapabilityKind, CapabilityMatrix, CapabilityState};

use super::capture::{CaptureProviderBuilder, CaptureProviderDescriptor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRegistry {
    capture_providers: Vec<CaptureProviderDescriptor>,
    platform_capabilities: Vec<CapabilityState>,
}

impl ProviderRegistry {
    pub fn with_default_platform(capture_providers: Vec<CaptureProviderDescriptor>) -> Self {
        let procfs_socket = ProcfsSocketResolver::new();
        Self::with_default_platform_and_procfs_socket(
            capture_providers,
            procfs_socket.capabilities(),
        )
    }

    pub fn with_default_platform_and_procfs_socket(
        capture_providers: Vec<CaptureProviderDescriptor>,
        procfs_socket_capabilities: Vec<CapabilityState>,
    ) -> Self {
        let procfs = ProcfsAttributor::new();
        Self::new(
            capture_providers,
            default_platform_capabilities(procfs)
                .into_iter()
                .chain(procfs_socket_capabilities)
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

fn default_platform_capabilities(
    procfs: impl ProcessAttributor,
) -> impl IntoIterator<Item = CapabilityState> {
    [
        CapabilityState::unavailable(
            CapabilityKind::LibsslUprobe,
            "libssl uprobe attach candidate discovery and attach planning code exists, but it is not wired into runtime and the uprobe loader and plaintext event provider are not implemented in this build",
        ),
        CapabilityState::available(CapabilityKind::Http1),
        CapabilityState::available(CapabilityKind::Sse),
        CapabilityState::available(CapabilityKind::WebSocketHandoff),
        CapabilityState::available(CapabilityKind::WebSocketFrame),
        CapabilityState::degraded(
            CapabilityKind::LuaJit,
            "policy runtime is wired into replay and live capture, but hot reload and multiple active bundles are not implemented",
        ),
        CapabilityState::degraded(
            CapabilityKind::DurableSpool,
            "ingress recovery can replay persisted capture events, including bytes, gaps, and connection lifecycle events, and advances the parser cursor only when active parser state has been removed, but recovery is at-least-once, replays under the current config and policy, and durable parser checkpoints plus processing provenance are not complete",
        ),
        CapabilityState::degraded(
            CapabilityKind::IngressJournal,
            "ingress recovery replays persisted capture events before opening a capture provider and only advances the parser cursor when active parser state has been removed, but durable parser checkpoints and processing provenance are not complete",
        ),
        CapabilityState::available(CapabilityKind::ExportQueue),
        CapabilityState::degraded(
            CapabilityKind::WebhookExporter,
            "webhook transport can drain planned export sinks with configured fixed worker bounds, per-sink batch quota, cursor-safe bounded export queue cleanup, and per-sink exponential failure backoff during run and replay CLI webhook output during replay, but retention deadline is not implemented",
        ),
        CapabilityState::available(CapabilityKind::DryRunEnforcement),
    ]
    .into_iter()
    .chain(procfs.capabilities())
}
