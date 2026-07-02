use std::collections::BTreeSet;

use serde::Serialize;

macro_rules! define_e2e_capabilities {
    ($(
        $variant:ident => {
            id: $id:literal,
            label: $label:literal,
            category: $category:ident,
        }
    ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        pub(super) enum E2eCapability {
            $($variant),+
        }

        impl E2eCapability {
            pub(super) const ALL: &'static [Self] = &[
                $(Self::$variant),+
            ];

            pub(super) const fn id(self) -> &'static str {
                match self {
                    $(Self::$variant => $id),+
                }
            }

            const fn label(self) -> &'static str {
                match self {
                    $(Self::$variant => $label),+
                }
            }

            const fn category(self) -> E2eCapabilityCategory {
                match self {
                    $(Self::$variant => E2eCapabilityCategory::$category),+
                }
            }
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub(super) enum E2eCapabilityCategory {
    CaptureInput,
    Protocol,
    StorageExport,
    Policy,
    Admin,
    Enforcement,
    Tls,
    Interception,
    Mitm,
    LinuxArtifact,
}

impl E2eCapabilityCategory {
    const fn id(self) -> &'static str {
        match self {
            Self::CaptureInput => "capture_input",
            Self::Protocol => "protocol",
            Self::StorageExport => "storage_export",
            Self::Policy => "policy",
            Self::Admin => "admin",
            Self::Enforcement => "enforcement",
            Self::Tls => "tls",
            Self::Interception => "interception",
            Self::Mitm => "mitm",
            Self::LinuxArtifact => "linux_artifact",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::CaptureInput => "capture input",
            Self::Protocol => "protocol",
            Self::StorageExport => "storage/export",
            Self::Policy => "policy",
            Self::Admin => "admin",
            Self::Enforcement => "enforcement",
            Self::Tls => "TLS",
            Self::Interception => "interception",
            Self::Mitm => "MITM",
            Self::LinuxArtifact => "Linux artifact",
        }
    }
}

define_e2e_capabilities! {
    ReplayPipeline => {
        id: "replay_pipeline",
        label: "replay pipeline",
        category: CaptureInput,
    },
    PlaintextFeed => {
        id: "plaintext_feed",
        label: "plaintext feed",
        category: CaptureInput,
    },
    CaptureLossEvent => {
        id: "capture_loss_event",
        label: "capture loss event",
        category: CaptureInput,
    },
    GapSemantics => {
        id: "gap_semantics",
        label: "gap semantics",
        category: CaptureInput,
    },
    HttpParsing => {
        id: "http_parsing",
        label: "HTTP parsing",
        category: Protocol,
    },
    SseParsing => {
        id: "sse_parsing",
        label: "SSE parsing",
        category: Protocol,
    },
    WebSocketParsing => {
        id: "websocket_parsing",
        label: "WebSocket parsing",
        category: Protocol,
    },
    DurableSpoolExport => {
        id: "durable_spool_export",
        label: "durable spool/export",
        category: StorageExport,
    },
    WebhookExport => {
        id: "webhook_export",
        label: "webhook export",
        category: StorageExport,
    },
    FileExport => {
        id: "file_export",
        label: "file export",
        category: StorageExport,
    },
    LuaPolicyBundle => {
        id: "lua_policy_bundle",
        label: "Lua policy bundle",
        category: Policy,
    },
    RemotePolicyBundle => {
        id: "remote_policy_bundle",
        label: "remote policy bundle",
        category: Policy,
    },
    RemotePolicyPolling => {
        id: "remote_policy_polling",
        label: "remote policy polling",
        category: Policy,
    },
    RemoteEnforcementPolicy => {
        id: "remote_enforcement_policy",
        label: "remote enforcement policy",
        category: Policy,
    },
    LibpcapLiveCapture => {
        id: "libpcap_live_capture",
        label: "libpcap live capture",
        category: CaptureInput,
    },
    AdminReload => {
        id: "admin_reload",
        label: "admin reload",
        category: Admin,
    },
    SocketDestroyEnforcement => {
        id: "socket_destroy_enforcement",
        label: "socket destroy enforcement",
        category: Enforcement,
    },
    TlsSessionSecretMaterial => {
        id: "tls_session_secret_material",
        label: "TLS session-secret material",
        category: Tls,
    },
    TlsKeyLogMaterial => {
        id: "tls_keylog_material",
        label: "TLS key log material",
        category: Tls,
    },
    ProcessEbpfObservation => {
        id: "process_ebpf_observation",
        label: "process eBPF observation",
        category: CaptureInput,
    },
    ProcessEbpfOutputLoss => {
        id: "process_ebpf_output_loss",
        label: "process eBPF output loss",
        category: CaptureInput,
    },
    LibsslPlaintext => {
        id: "libssl_plaintext",
        label: "libssl plaintext",
        category: Tls,
    },
    TlsPlaintextOutputLoss => {
        id: "tls_plaintext_output_loss",
        label: "TLS plaintext output loss",
        category: Tls,
    },
    TransparentInbound => {
        id: "transparent_inbound",
        label: "transparent inbound interception",
        category: Interception,
    },
    TransparentOutbound => {
        id: "transparent_outbound",
        label: "transparent outbound interception",
        category: Interception,
    },
    ProcessScopedInterception => {
        id: "process_scoped_interception",
        label: "process-scoped interception",
        category: Interception,
    },
    FlowClassifiedInterception => {
        id: "flow_classified_interception",
        label: "flow-classified interception",
        category: Interception,
    },
    OwnerScopedInterception => {
        id: "owner_scoped_interception",
        label: "owner-scoped interception",
        category: Interception,
    },
    MitmPlaintextBridge => {
        id: "mitm_plaintext_bridge",
        label: "MITM plaintext bridge",
        category: Mitm,
    },
    MitmPolicyHook => {
        id: "mitm_policy_hook",
        label: "MITM policy hook",
        category: Mitm,
    },
    ManagedMitmBackend => {
        id: "managed_mitm_backend",
        label: "managed MITM backend",
        category: Mitm,
    },
    ProductMitmHttps => {
        id: "product_mitm_https",
        label: "product MITM HTTPS",
        category: Mitm,
    },
    ProductMitmDnsDiscovery => {
        id: "product_mitm_dns_discovery",
        label: "product MITM DNS discovery",
        category: Mitm,
    },
    ProductMitmWebSocket => {
        id: "product_mitm_websocket",
        label: "product MITM WebSocket",
        category: Mitm,
    },
    LinuxTransparentArtifact => {
        id: "linux_transparent_artifact",
        label: "Linux transparent artifact",
        category: LinuxArtifact,
    },
    LinuxCgroupArtifact => {
        id: "linux_cgroup_artifact",
        label: "Linux cgroup artifact",
        category: LinuxArtifact,
    },
}

pub(super) fn capability_ids(capabilities: &[E2eCapability]) -> Vec<&'static str> {
    capabilities
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(E2eCapability::id)
        .collect()
}

pub(super) fn capability_summary(capabilities: &[E2eCapability]) -> String {
    capability_ids(capabilities).join(",")
}

pub(super) fn inventory_rows() -> Vec<E2eCapabilityInventoryRow> {
    E2eCapability::ALL
        .iter()
        .copied()
        .map(E2eCapabilityInventoryRow::from_capability)
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct E2eCapabilityInventoryRow {
    pub(super) id: &'static str,
    pub(super) label: &'static str,
    pub(super) category: E2eCapabilityCategoryInventoryRow,
}

impl E2eCapabilityInventoryRow {
    fn from_capability(capability: E2eCapability) -> Self {
        Self {
            id: capability.id(),
            label: capability.label(),
            category: E2eCapabilityCategoryInventoryRow::from_category(capability.category()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(super) struct E2eCapabilityCategoryInventoryRow {
    pub(super) id: &'static str,
    pub(super) label: &'static str,
}

impl E2eCapabilityCategoryInventoryRow {
    fn from_category(category: E2eCapabilityCategory) -> Self {
        Self {
            id: category.id(),
            label: category.label(),
        }
    }
}
