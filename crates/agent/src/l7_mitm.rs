use probe_config::AgentConfig;
use probe_core::{CapabilityKind, CapabilityState, RuntimeMode};

pub(crate) struct L7MitmRuntime {
    capability: CapabilityState,
}

impl L7MitmRuntime {
    pub(crate) fn capability(&self) -> CapabilityState {
        self.capability.clone()
    }
}

pub(crate) fn resolve(config: &AgentConfig) -> L7MitmRuntime {
    let interception = &config.enforcement.interception;
    if !interception.strategy.is_mitm() {
        return unavailable(
            "L7 MITM backend is not configured; select a MITM interception strategy to require it",
        );
    }
    if let Err(error) = config.validate_l7_mitm_contract() {
        return unavailable(format!("L7 MITM backend contract is invalid: {error}"));
    }

    L7MitmRuntime {
        capability: CapabilityState {
            kind: CapabilityKind::L7Mitm,
            mode: RuntimeMode::Available,
            reason: Some(
                "external selector-scoped L7 MITM backend contract is configured; agent redirects matching flows to the external listener but does not manage the L7 proxy process yet"
                    .to_string(),
            ),
        },
    }
}

fn unavailable(reason: impl Into<String>) -> L7MitmRuntime {
    L7MitmRuntime {
        capability: CapabilityState::unavailable(CapabilityKind::L7Mitm, reason),
    }
}
