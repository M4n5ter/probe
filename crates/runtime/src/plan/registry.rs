use attribution::{ProcessAttributor, ProcfsAttributor, ProcfsSocketResolver};
use probe_config::CaptureBackend;
use probe_core::{CapabilityKind, CapabilityMatrix, CapabilityState};

use super::capture::{CaptureProviderBuilder, CaptureProviderDescriptor};

const DEFAULT_L7_MITM_UNAVAILABLE_REASON: &str = concat!(
    "L7 MITM control-plane support exists for selector-scoped external or managed backends, ",
    "readiness probes, operator-managed client trust contracts, material refs, ",
    "plaintext bridge provenance, product proxy downstream and upstream TLS relay, ",
    "downstream SNI propagation to upstream TLS server names, explicit product proxy ",
    "host-to-upstream routes, opt-in DNS upstream discovery, typed HTTP/1.1 ALPN policy, ",
    "proxy-side policy hooks, and product proxy transparent inbound/outbound HTTPS ",
    "routed and DNS-discovered allow-path and deny-path validation, ",
    "but no MITM backend is configured; default whole-machine transparent MITM is rejected, ",
    "and HTTP/2+ ALPN dispatch/routing, strong original attribution, automatic client ",
    "trust store installation, and non-HTTP transparent allow-path matrices remain unavailable"
);

pub fn default_l7_mitm_unavailable_reason() -> &'static str {
    DEFAULT_L7_MITM_UNAVAILABLE_REASON
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderRegistry {
    capture_providers: Vec<CaptureProviderDescriptor>,
    platform_capabilities: Vec<CapabilityState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformProbeResults {
    pub procfs_socket: Vec<CapabilityState>,
    pub connection_enforcement: CapabilityState,
    pub transparent_interception: CapabilityState,
    pub transparent_process_classifier: CapabilityState,
    pub transparent_flow_classifier: CapabilityState,
    pub l7_mitm: CapabilityState,
    pub libssl_uprobe: CapabilityState,
}

impl PlatformProbeResults {
    pub fn from_host_defaults() -> Self {
        let procfs_socket = ProcfsSocketResolver::new().capabilities();
        Self {
            procfs_socket,
            connection_enforcement: default_connection_enforcement_capability(),
            transparent_interception: default_transparent_interception_capability(),
            transparent_process_classifier: Self::default_transparent_process_classifier(),
            transparent_flow_classifier: Self::default_transparent_flow_classifier(),
            l7_mitm: default_l7_mitm_capability(),
            libssl_uprobe: default_libssl_uprobe_capability(),
        }
    }

    pub fn default_transparent_process_classifier() -> CapabilityState {
        CapabilityState::unavailable(
            CapabilityKind::TransparentProcessClassifier,
            "transparent process classifier capability is not provided by this runtime registry",
        )
    }

    pub fn default_transparent_flow_classifier() -> CapabilityState {
        CapabilityState::unavailable(
            CapabilityKind::TransparentFlowClassifier,
            "transparent flow classifier backend is not configured; not/ref transparent interception selectors and any selectors with classifier-only or unconstrained setup branches require flow-aware classification before rule installation",
        )
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
                platform.transparent_interception,
                platform.transparent_process_classifier,
                platform.transparent_flow_classifier,
                platform.l7_mitm,
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
    transparent_interception_capability: CapabilityState,
    transparent_process_classifier_capability: CapabilityState,
    transparent_flow_classifier_capability: CapabilityState,
    l7_mitm_capability: CapabilityState,
    libssl_uprobe_capability: CapabilityState,
) -> impl IntoIterator<Item = CapabilityState> {
    [
        libssl_uprobe_capability,
        CapabilityState::available(CapabilityKind::TlsSessionSecretRecordDecrypt),
        l7_mitm_capability,
        CapabilityState::available(CapabilityKind::Http1),
        CapabilityState::available(CapabilityKind::Sse),
        CapabilityState::available(CapabilityKind::WebSocketHandoff),
        CapabilityState::available(CapabilityKind::WebSocketFrame),
        CapabilityState::degraded(
            CapabilityKind::WebSocketMessage,
            "WebSocket parser emits complete text/binary message metadata up to 16 MiB for non-extension payloads; oversized messages keep frame metadata and omit websocket_message, while extension-compressed payloads and full message storage are not supported",
        ),
        CapabilityState::degraded(
            CapabilityKind::PolicyRuntime,
            "policy runtime is wired into replay and live capture, including multiple active bundles, runtime error audit, manual admin policy bundle reload, and explicit local policy bundle watcher reload, but main config reload, remote control-plane updates, and policy state migration are not implemented",
        ),
        CapabilityState::degraded(
            CapabilityKind::DurableSpool,
            "ingress recovery can replay persisted capture events, including bytes, gaps, and connection lifecycle events, pipeline export events carry ingress provenance for stable replay ids, pipeline-generated retained export records are deduplicated by event id, and parser recovery advances a durable safe-prefix cursor, but recovery replays under the current config and policy and active parser state is not serialized",
        ),
        CapabilityState::degraded(
            CapabilityKind::IngressJournal,
            "ingress recovery replays persisted capture events before opening a capture provider, pipeline export events carry ingress provenance, and the parser cursor advances only when every flow is checkpoint-safe, but active parser state is not serialized",
        ),
        CapabilityState::available(CapabilityKind::ExportQueue),
        CapabilityState::available(CapabilityKind::WebhookExporter),
        CapabilityState::available(CapabilityKind::DryRunEnforcement),
        connection_enforcement_capability,
        transparent_interception_capability,
        transparent_process_classifier_capability,
        transparent_flow_classifier_capability,
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

fn default_transparent_interception_capability() -> CapabilityState {
    CapabilityState::unavailable(
        CapabilityKind::TransparentInterception,
        "transparent interception is not configured; Linux nftables lifecycle is resolved by the agent composition root when a transparent strategy is explicitly enabled",
    )
}

fn default_libssl_uprobe_capability() -> CapabilityState {
    CapabilityState::unavailable(
        CapabilityKind::LibsslUprobe,
        "libssl uprobe discovery, attach planning, ABI, capture adapter, userspace uprobe loader, and eBPF producer exist, but no agent runtime composition root supplied a TLS plaintext provider capability",
    )
}

fn default_l7_mitm_capability() -> CapabilityState {
    CapabilityState::unavailable(CapabilityKind::L7Mitm, default_l7_mitm_unavailable_reason())
}

#[cfg(test)]
mod tests {
    use probe_core::RuntimeMode;

    use super::*;

    #[test]
    fn available_provider_requires_matching_executable_builder() {
        let registry = ProviderRegistry::new(
            vec![capture_provider(
                CaptureBackend::Ebpf,
                CaptureProviderBuilder::Unimplemented,
                RuntimeMode::Available,
            )],
            Vec::new(),
        );

        let provider = registry.capture_provider(CaptureBackend::Ebpf);

        assert_eq!(provider.capability_mode, RuntimeMode::Unavailable);
        assert!(
            provider
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("Unimplemented builder"))
        );
        assert_eq!(
            registry.capability_matrix().mode(CapabilityKind::Ebpf),
            RuntimeMode::Unavailable
        );
    }

    #[test]
    fn ingress_journal_recovery_is_degraded_until_active_parser_state_is_durable() {
        let registry = ProviderRegistry::with_default_platform(vec![capture_provider(
            CaptureBackend::Replay,
            CaptureProviderBuilder::Replay,
            RuntimeMode::Available,
        )]);
        let matrix = registry.capability_matrix();

        assert_eq!(
            matrix.mode(CapabilityKind::IngressJournal),
            RuntimeMode::Degraded
        );
        assert_eq!(
            matrix.mode(CapabilityKind::DurableSpool),
            RuntimeMode::Degraded
        );
        assert!(
            matrix
                .states()
                .iter()
                .find(|state| state.kind == CapabilityKind::DurableSpool)
                .and_then(|state| state.reason.as_deref())
                .is_some_and(|reason| reason.contains("active parser state is not serialized"))
        );
        assert!(
            matrix
                .states()
                .iter()
                .find(|state| state.kind == CapabilityKind::IngressJournal)
                .and_then(|state| state.reason.as_deref())
                .is_some_and(|reason| reason.contains("checkpoint-safe"))
        );
    }

    #[test]
    fn websocket_parser_capabilities_are_supported() {
        let registry = ProviderRegistry::with_default_platform(vec![capture_provider(
            CaptureBackend::Replay,
            CaptureProviderBuilder::Replay,
            RuntimeMode::Available,
        )]);
        let matrix = registry.capability_matrix();

        assert_eq!(
            matrix.mode(CapabilityKind::WebSocketHandoff),
            RuntimeMode::Available
        );
        assert_eq!(
            matrix.mode(CapabilityKind::WebSocketFrame),
            RuntimeMode::Available
        );
        assert_eq!(
            matrix.mode(CapabilityKind::WebSocketMessage),
            RuntimeMode::Degraded
        );
    }

    #[test]
    fn l7_mitm_is_reported_as_unavailable_target_capability() {
        let registry = ProviderRegistry::with_default_platform(vec![capture_provider(
            CaptureBackend::Replay,
            CaptureProviderBuilder::Replay,
            RuntimeMode::Available,
        )]);
        let state = registry.capability_matrix().state(CapabilityKind::L7Mitm);

        assert_eq!(state.mode, RuntimeMode::Unavailable);
        let reason = state
            .reason
            .expect("L7 MITM target capability should explain why it is unavailable");
        assert!(reason.contains("control-plane support exists"));
        assert!(reason.contains("no MITM backend is configured"));
        assert!(reason.contains("default whole-machine transparent MITM is rejected"));
        assert!(reason.contains("product proxy downstream and upstream TLS relay"));
        assert!(reason.contains("upstream TLS relay"));
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
}
