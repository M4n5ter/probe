use attribution::{ProcessAttributor, ProcfsAttributor, ProcfsSocketResolver};
use probe_config::CaptureBackend;
use probe_core::{CapabilityKind, CapabilityMatrix, CapabilityState};

use super::capture::{CaptureProviderBuilder, CaptureProviderDescriptor};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRegistry {
    capture_providers: Vec<CaptureProviderDescriptor>,
    platform_capabilities: Vec<CapabilityState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformProbeResults {
    pub procfs_socket: Vec<CapabilityState>,
    pub connection_enforcement: CapabilityState,
    pub libssl_uprobe: CapabilityState,
}

impl PlatformProbeResults {
    pub fn from_host_defaults() -> Self {
        Self {
            procfs_socket: ProcfsSocketResolver::new().capabilities(),
            connection_enforcement: default_connection_enforcement_capability(),
            libssl_uprobe: default_libssl_uprobe_capability(),
        }
    }
}

impl ProviderRegistry {
    pub fn with_default_platform(capture_providers: Vec<CaptureProviderDescriptor>) -> Self {
        Self::with_platform_probes(
            capture_providers,
            PlatformProbeResults::from_host_defaults(),
        )
    }

    pub fn with_platform_probes(
        capture_providers: Vec<CaptureProviderDescriptor>,
        platform: PlatformProbeResults,
    ) -> Self {
        let procfs = ProcfsAttributor::new();
        Self::new(
            capture_providers,
            default_platform_capabilities(
                procfs,
                platform.connection_enforcement,
                platform.libssl_uprobe,
            )
            .into_iter()
            .chain(platform.procfs_socket)
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
    connection_enforcement_capability: CapabilityState,
    libssl_uprobe_capability: CapabilityState,
) -> impl IntoIterator<Item = CapabilityState> {
    [
        libssl_uprobe_capability,
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
        CapabilityState::available(CapabilityKind::WebhookExporter),
        CapabilityState::available(CapabilityKind::DryRunEnforcement),
        connection_enforcement_capability,
    ]
    .into_iter()
    .chain(procfs.capabilities())
}

fn default_connection_enforcement_capability() -> CapabilityState {
    CapabilityState::unavailable(
        CapabilityKind::ConnectionEnforcement,
        "connection-level enforcement backend abstraction is wired, but no executable blocking backend is configured",
    )
}

fn default_libssl_uprobe_capability() -> CapabilityState {
    CapabilityState::unavailable(
        CapabilityKind::LibsslUprobe,
        "libssl uprobe discovery, attach planning, ABI, capture adapter, userspace uprobe loader, and eBPF producer exist, but agent dynamic attach lifecycle and flow resolver runtime wiring are not implemented in this build",
    )
}
