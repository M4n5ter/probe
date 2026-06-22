use enforcement::EnforcementBackend;
use probe_config::AgentConfig;
use probe_core::CapabilityMatrix;
use runtime::{ProviderRegistry, RuntimePlan, TransparentInterceptionExecutionPlan};

use crate::{
    capture_registry::default_provider_registry,
    connection_enforcement::{self, ConnectionEnforcementRuntime},
    error::AgentError,
    transparent_interception::{self, TransparentInterceptionRuntime},
};

pub(crate) struct RuntimeComposition {
    plan: RuntimePlan,
    connection_enforcement: ConnectionEnforcementRuntime,
    transparent_interception: TransparentInterceptionRuntime,
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

    pub(crate) fn into_run_parts(
        self,
    ) -> (
        RuntimePlan,
        Option<Box<dyn EnforcementBackend>>,
        TransparentInterceptionRuntime,
    ) {
        (
            self.plan,
            self.connection_enforcement.into_backend(),
            self.transparent_interception,
        )
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
        transparent_interception,
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
    let transparent_interception_execution =
        TransparentInterceptionExecutionPlan::try_from_config(&config.enforcement.interception);
    let transparent_interception = match transparent_interception_execution {
        Ok(execution_plan) => transparent_interception::resolve(execution_plan),
        Err(error) => transparent_interception::unavailable_for_config_error(error.to_string()),
    };
    (
        connection_enforcement::resolve(config.enforcement.backend),
        transparent_interception,
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
    use probe_core::{
        CapabilityKind, Direction, EnforcementMode, ProcessSelector, RuntimeMode, Selector,
        TrafficSelector,
    };

    use super::*;

    #[test]
    fn default_composition_has_no_executable_enforcement_backend() {
        let composition = build_runtime_composition(AgentConfig::default())
            .expect("default composition should build");
        let (_plan, backend) = composition.into_enforcement_parts();

        assert!(backend.is_none());
    }

    #[test]
    fn outbound_mitm_runtime_fails_closed_until_proxy_lifecycle_exists() {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundMitm;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let error = match build_runtime_composition(config) {
            Ok(_) => panic!("outbound MITM must not be executable without proxy lifecycle"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("proxy self-bypass"));
    }

    #[test]
    fn invalid_transparent_proxy_plan_does_not_panic_during_capability_probe() {
        let mut config = AgentConfig::default();
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.proxy.health_probe.target =
            Some("not-a-socket-address".to_string());

        let capabilities = capability_matrix_for_config(&config);
        let transparent_interception = capabilities
            .states()
            .iter()
            .find(|state| state.kind == CapabilityKind::TransparentInterception)
            .expect("transparent interception capability should be reported");

        assert_eq!(transparent_interception.mode, RuntimeMode::Unavailable);
        assert!(
            transparent_interception
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("IP socket address"))
        );

        let error = match build_runtime_composition(config) {
            Ok(_) => panic!("runtime build should still return a config validation error"),
            Err(error) => error,
        };

        assert!(error.to_string().contains("health_probe.target"));
    }
}
