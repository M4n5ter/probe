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
    (
        connection_enforcement::resolve(config.enforcement.backend),
        transparent_interception::resolve(
            &config.enforcement.interception,
            config.enforcement.selector.as_ref(),
        ),
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
    use probe_core::{Direction, EnforcementMode, ProcessSelector, Selector, TrafficSelector};

    use super::*;

    #[test]
    fn default_composition_has_no_executable_enforcement_backend() {
        let composition = build_runtime_composition(AgentConfig::default())
            .expect("default composition should build");
        let (_plan, backend) = composition.into_enforcement_parts();

        assert!(backend.is_none());
    }

    #[test]
    fn process_scoped_transparent_interception_setup_fails_closed() {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxy;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector {
                names: vec!["curl".to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector::default(),
        ));
        let error = match build_runtime_composition(config) {
            Ok(_) => panic!("transparent interception should be unavailable"),
            Err(error) => error,
        };

        assert!(
            error
                .to_string()
                .contains("process constraints cannot be represented")
        );
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
}
