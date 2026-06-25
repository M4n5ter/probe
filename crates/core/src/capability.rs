use serde::{Deserialize, Deserializer, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    ReplayCapture,
    Ebpf,
    Libpcap,
    ProcfsAttribution,
    ProcfsSocketAttribution,
    LibsslUprobe,
    TlsSessionSecretRecordDecrypt,
    #[serde(rename = "l7_mitm")]
    L7Mitm,
    ExternalPlaintextFeed,
    CaptureEventFeed,
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
    TransparentProcessClassifier,
    TransparentFlowClassifier,
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
            Self::TlsSessionSecretRecordDecrypt => "tls_session_secret_record_decrypt",
            Self::L7Mitm => "l7_mitm",
            Self::ExternalPlaintextFeed => "external_plaintext_feed",
            Self::CaptureEventFeed => "capture_event_feed",
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
            Self::TransparentProcessClassifier => "transparent_process_classifier",
            Self::TransparentFlowClassifier => "transparent_flow_classifier",
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

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CapabilityMatrix {
    states: Vec<CapabilityState>,
}

impl<'de> Deserialize<'de> for CapabilityMatrix {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Wire {
            states: Vec<CapabilityState>,
        }

        let wire = Wire::deserialize(deserializer)?;
        Ok(Self::new(wire.states))
    }
}

impl CapabilityMatrix {
    pub fn new(states: impl IntoIterator<Item = CapabilityState>) -> Self {
        let mut normalized: Vec<CapabilityState> = Vec::new();
        for state in states {
            if let Some(existing) = normalized
                .iter_mut()
                .find(|existing| existing.kind == state.kind)
            {
                *existing = state;
            } else {
                normalized.push(state);
            }
        }
        Self { states: normalized }
    }

    pub fn states(&self) -> &[CapabilityState] {
        &self.states
    }

    pub fn reported_state(&self, kind: CapabilityKind) -> Option<&CapabilityState> {
        self.states.iter().find(|state| state.kind == kind)
    }

    pub fn state(&self, kind: CapabilityKind) -> CapabilityState {
        self.reported_state(kind).cloned().unwrap_or_else(|| {
            CapabilityState::unavailable(
                kind,
                format!(
                    "capability {} is not reported by provider registry",
                    kind.wire_name()
                ),
            )
        })
    }

    pub fn mode(&self, kind: CapabilityKind) -> RuntimeMode {
        self.reported_state(kind)
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
            CapabilityKind::TlsSessionSecretRecordDecrypt,
            CapabilityKind::L7Mitm,
            CapabilityKind::ExternalPlaintextFeed,
            CapabilityKind::CaptureEventFeed,
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
            CapabilityKind::TransparentProcessClassifier,
            CapabilityKind::TransparentFlowClassifier,
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

    #[test]
    fn capability_matrix_state_preserves_reported_reason() {
        let matrix = CapabilityMatrix::new([CapabilityState::unavailable(
            CapabilityKind::TransparentProcessClassifier,
            "not built",
        )]);

        assert_eq!(
            matrix.state(CapabilityKind::TransparentProcessClassifier),
            CapabilityState::unavailable(CapabilityKind::TransparentProcessClassifier, "not built")
        );
    }

    #[test]
    fn capability_matrix_new_deduplicates_with_last_state_winning() {
        let matrix = CapabilityMatrix::new([
            CapabilityState::unavailable(
                CapabilityKind::TransparentProcessClassifier,
                "default unavailable",
            ),
            CapabilityState::available(CapabilityKind::TransparentProcessClassifier),
        ]);

        assert_eq!(
            matrix.states(),
            &[CapabilityState::available(
                CapabilityKind::TransparentProcessClassifier
            )]
        );
        assert_eq!(
            matrix.mode(CapabilityKind::TransparentProcessClassifier),
            RuntimeMode::Available
        );
    }

    #[test]
    fn capability_matrix_deserialization_deduplicates_with_last_state_winning()
    -> Result<(), serde_json::Error> {
        let matrix: CapabilityMatrix = serde_json::from_value(serde_json::json!({
            "states": [
                {
                    "kind": "transparent_process_classifier",
                    "mode": "unavailable",
                    "reason": "default unavailable"
                },
                {
                    "kind": "transparent_process_classifier",
                    "mode": "available",
                    "reason": null
                }
            ]
        }))?;

        assert_eq!(
            matrix.states(),
            &[CapabilityState::available(
                CapabilityKind::TransparentProcessClassifier
            )]
        );
        Ok(())
    }

    #[test]
    fn capability_matrix_state_reports_missing_capability() {
        let matrix = CapabilityMatrix::new([]);

        let state = matrix.state(CapabilityKind::TransparentProcessClassifier);

        assert_eq!(state.kind, CapabilityKind::TransparentProcessClassifier);
        assert_eq!(state.mode, RuntimeMode::Unavailable);
        assert!(
            state
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("not reported by provider registry"))
        );
    }
}
