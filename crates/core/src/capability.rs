use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityKind {
    Ebpf,
    Libpcap,
    ProcfsAttribution,
    LibsslUprobe,
    Http1,
    Sse,
    WebSocketHandoff,
    LuaJit,
    DurableSpool,
    WebhookExporter,
    DryRunEnforcement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeMode {
    Available,
    Degraded,
    Unavailable,
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
