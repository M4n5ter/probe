use probe_core::{CapabilityKind, EnforcementMode, RuntimeMode};
use runtime::RuntimePlan;
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnforcementStatusSnapshot {
    pub configured_mode: EnforcementMode,
    pub status: EnforcementStatusMode,
    pub selector_configured: bool,
    pub capability: EnforcementCapabilityStatusSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementStatusMode {
    Disabled,
    AuditOnly,
    DryRun,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum EnforcementCapabilityStatusSnapshot {
    NotRequired,
    Required {
        capability: CapabilityKind,
        mode: RuntimeMode,
    },
}

pub(super) fn enforcement_status(plan: &RuntimePlan) -> EnforcementStatusSnapshot {
    let configured_mode = plan.config.enforcement.mode;
    let (status, capability) = match configured_mode {
        EnforcementMode::Disabled => (
            EnforcementStatusMode::Disabled,
            EnforcementCapabilityStatusSnapshot::NotRequired,
        ),
        EnforcementMode::AuditOnly => (
            EnforcementStatusMode::AuditOnly,
            EnforcementCapabilityStatusSnapshot::NotRequired,
        ),
        EnforcementMode::DryRun => (
            EnforcementStatusMode::DryRun,
            EnforcementCapabilityStatusSnapshot::Required {
                capability: CapabilityKind::DryRunEnforcement,
                mode: plan.capabilities.mode(CapabilityKind::DryRunEnforcement),
            },
        ),
        EnforcementMode::Enforce => {
            unreachable!("runtime plan validation rejects real enforcement mode")
        }
    };

    EnforcementStatusSnapshot {
        configured_mode,
        status,
        selector_configured: plan.config.enforcement.selector.is_some(),
        capability,
    }
}
