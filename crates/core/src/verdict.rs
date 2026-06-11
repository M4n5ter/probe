use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Observe,
    Alert,
    Deny,
    Reset,
    Quarantine,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictScope {
    Flow,
    Request,
    Response,
    Chunk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    Disabled,
    AuditOnly,
    DryRun,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementOutcome {
    Disabled,
    AuditOnly,
    DryRun,
    SelectorMiss,
    Unsupported,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub action: Action,
    pub scope: VerdictScope,
    pub reason: String,
    pub confidence: u8,
    pub ttl_ms: Option<u64>,
}

impl Verdict {
    pub fn alert(reason: impl Into<String>) -> Self {
        Self {
            action: Action::Alert,
            scope: VerdictScope::Flow,
            reason: reason.into(),
            confidence: 100,
            ttl_ms: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnforcementDecision {
    pub mode: EnforcementMode,
    pub outcome: EnforcementOutcome,
    pub requested_action: Action,
    pub effective_action: Action,
    pub scope: VerdictScope,
    pub selector_matched: bool,
    pub reason: String,
}
