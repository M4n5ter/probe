use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

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

impl Action {
    pub fn is_protective(self) -> bool {
        matches!(self, Self::Deny | Self::Reset | Self::Quarantine)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtectiveActionProfile {
    actions: Vec<Action>,
}

impl ProtectiveActionProfile {
    pub fn new(actions: impl IntoIterator<Item = Action>) -> Result<Self, ProtectiveActionError> {
        let mut validated = Vec::new();
        for action in actions {
            if !action.is_protective() {
                return Err(ProtectiveActionError::Unsupported { action });
            }
            if !validated.contains(&action) {
                validated.push(action);
            }
        }
        if validated.is_empty() {
            return Err(ProtectiveActionError::Empty);
        }
        Ok(Self { actions: validated })
    }

    pub fn actions(&self) -> &[Action] {
        &self.actions
    }

    pub fn contains(&self, action: Action) -> bool {
        self.actions.contains(&action)
    }

    pub fn into_actions(self) -> Vec<Action> {
        self.actions
    }
}

impl Default for ProtectiveActionProfile {
    fn default() -> Self {
        Self {
            actions: vec![Action::Deny, Action::Reset, Action::Quarantine],
        }
    }
}

impl Serialize for ProtectiveActionProfile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.actions.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ProtectiveActionProfile {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Vec::<Action>::deserialize(deserializer)
            .and_then(|actions| Self::new(actions).map_err(serde::de::Error::custom))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ProtectiveActionError {
    #[error("protective action profile cannot be empty")]
    Empty,
    #[error("action {action:?} is not a protective enforcement action")]
    Unsupported { action: Action },
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
