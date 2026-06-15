use enforcement::EnforcementBackend;
use probe_config::AgentConfig;
use probe_core::CapabilityMatrix;
use runtime::{ProviderRegistry, RuntimePlan};

use crate::{
    capture_registry::default_provider_registry,
    connection_enforcement::{self, ConnectionEnforcementRuntime},
    error::AgentError,
    transparent_interception::{self, TransparentInterceptionRuntime},
};

pub(crate) struct RuntimeComposition {
    plan: RuntimePlan,
    connection_enforcement: ConnectionEnforcementRuntime,
}

impl RuntimeComposition {
    pub(crate) fn into_plan(self) -> RuntimePlan {
        self.plan
    }

    pub(crate) fn into_enforcement_parts(
        self,
    ) -> (RuntimePlan, Option<Box<dyn EnforcementBackend>>) {
        (self.plan, self.connection_enforcement.into_backend())
    }
}

pub(crate) fn build_runtime_composition(
    config: AgentConfig,
) -> Result<RuntimeComposition, AgentError> {
    let (connection_enforcement, transparent_interception) = execution_runtimes_for_config(&config);
    let registry =
        provider_registry_for_runtimes(&config, &connection_enforcement, &transparent_interception);
    let plan = RuntimePlan::build(config, &registry).map_err(AgentError::Runtime)?;
    Ok(RuntimeComposition {
        plan,
        connection_enforcement,
    })
}

pub(crate) fn capability_matrix_for_config(config: &AgentConfig) -> CapabilityMatrix {
    let (connection_enforcement, transparent_interception) = execution_runtimes_for_config(config);
    provider_registry_for_runtimes(config, &connection_enforcement, &transparent_interception)
        .capability_matrix()
}

fn execution_runtimes_for_config(
    config: &AgentConfig,
) -> (ConnectionEnforcementRuntime, TransparentInterceptionRuntime) {
    (
        connection_enforcement::resolve(config.enforcement.backend),
        transparent_interception::resolve(&config.enforcement.interception),
    )
}

fn provider_registry_for_runtimes(
    config: &AgentConfig,
    connection_enforcement: &ConnectionEnforcementRuntime,
    transparent_interception: &TransparentInterceptionRuntime,
) -> ProviderRegistry {
    default_provider_registry(
        config,
        connection_enforcement.capability(),
        transparent_interception.capability(),
    )
}

#[cfg(test)]
mod tests {
    use probe_config::{CaptureSelection, TransparentInterceptionStrategyConfig};
    use probe_core::EnforcementMode;

    use super::*;

    #[test]
    fn default_composition_has_no_executable_enforcement_backend() {
        let composition = build_runtime_composition(AgentConfig::default())
            .expect("default composition should build");
        let (_plan, backend) = composition.into_enforcement_parts();

        assert!(backend.is_none());
    }

    #[test]
    fn transparent_interception_surface_has_no_executable_backend() {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        let error = match build_runtime_composition(config) {
            Ok(_) => panic!("transparent interception should be unavailable"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("no executable backend is configured")
        );
    }
}
