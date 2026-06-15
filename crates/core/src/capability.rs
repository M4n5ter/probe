use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    ReplayCapture,
    Ebpf,
    Libpcap,
    ProcfsAttribution,
    ProcfsSocketAttribution,
    LibsslUprobe,
    ExternalPlaintextFeed,
    Http1,
    Sse,
    #[serde(rename = "websocket_handoff")]
    WebSocketHandoff,
    #[serde(rename = "websocket_frame")]
    WebSocketFrame,
    LuaJit,
    DurableSpool,
    IngressJournal,
    ExportQueue,
    WebhookExporter,
    DryRunEnforcement,
    ConnectionEnforcement,
    TransparentInterception,
}

impl CapabilityKind {
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::ReplayCapture => "replay_capture",
            Self::Ebpf => "ebpf",
            Self::Libpcap => "libpcap",
            Self::ProcfsAttribution => "procfs_attribution",
            Self::ProcfsSocketAttribution => "procfs_socket_attribution",
            Self::LibsslUprobe => "libssl_uprobe",
            Self::ExternalPlaintextFeed => "external_plaintext_feed",
            Self::Http1 => "http1",
            Self::Sse => "sse",
            Self::WebSocketHandoff => "websocket_handoff",
            Self::WebSocketFrame => "websocket_frame",
            Self::LuaJit => "lua_jit",
            Self::DurableSpool => "durable_spool",
            Self::IngressJournal => "ingress_journal",
            Self::ExportQueue => "export_queue",
            Self::WebhookExporter => "webhook_exporter",
            Self::DryRunEnforcement => "dry_run_enforcement",
            Self::ConnectionEnforcement => "connection_enforcement",
            Self::TransparentInterception => "transparent_interception",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Available,
    Degraded,
    Unavailable,
}

impl RuntimeMode {
    pub fn wire_name(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Degraded => "degraded",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityState {
    pub kind: CapabilityKind,
    pub mode: RuntimeMode,
    pub reason: Option<String>,
}

impl CapabilityState {
    pub fn available(kind: CapabilityKind) -> Self {
        Self {
            kind,
            mode: RuntimeMode::Available,
            reason: None,
        }
    }

    pub fn degraded(kind: CapabilityKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            mode: RuntimeMode::Degraded,
            reason: Some(reason.into()),
        }
    }

    pub fn unavailable(kind: CapabilityKind, reason: impl Into<String>) -> Self {
        Self {
            kind,
            mode: RuntimeMode::Unavailable,
            reason: Some(reason.into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityRequirement {
    pub required: Vec<CapabilityKind>,
    pub preferred: Vec<CapabilityKind>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityMatrix {
    states: Vec<CapabilityState>,
}

impl CapabilityMatrix {
    pub fn new(states: impl IntoIterator<Item = CapabilityState>) -> Self {
        Self {
            states: states.into_iter().collect(),
        }
    }

    pub fn states(&self) -> &[CapabilityState] {
        &self.states
    }

    pub fn mode(&self, kind: CapabilityKind) -> RuntimeMode {
        self.states
            .iter()
            .find(|state| state.kind == kind)
            .map_or(RuntimeMode::Unavailable, |state| state.mode)
    }

    pub fn has_required(&self, requirements: &CapabilityRequirement) -> bool {
        requirements
            .required
            .iter()
            .all(|kind| self.mode(*kind) != RuntimeMode::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_kind_wire_name_matches_json_name() -> Result<(), serde_json::Error> {
        for kind in [
            CapabilityKind::ReplayCapture,
            CapabilityKind::Ebpf,
            CapabilityKind::Libpcap,
            CapabilityKind::ProcfsAttribution,
            CapabilityKind::ProcfsSocketAttribution,
            CapabilityKind::LibsslUprobe,
            CapabilityKind::ExternalPlaintextFeed,
            CapabilityKind::Http1,
            CapabilityKind::Sse,
            CapabilityKind::WebSocketHandoff,
            CapabilityKind::WebSocketFrame,
            CapabilityKind::LuaJit,
            CapabilityKind::DurableSpool,
            CapabilityKind::IngressJournal,
            CapabilityKind::ExportQueue,
            CapabilityKind::WebhookExporter,
            CapabilityKind::DryRunEnforcement,
            CapabilityKind::ConnectionEnforcement,
            CapabilityKind::TransparentInterception,
        ] {
            assert_eq!(serde_json::to_value(kind)?, kind.wire_name());
        }
        Ok(())
    }

    #[test]
    fn runtime_mode_wire_name_matches_json_name() -> Result<(), serde_json::Error> {
        for mode in [
            RuntimeMode::Available,
            RuntimeMode::Degraded,
            RuntimeMode::Unavailable,
        ] {
            assert_eq!(serde_json::to_value(mode)?, mode.wire_name());
        }
        Ok(())
    }
}
