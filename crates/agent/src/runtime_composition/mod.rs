use enforcement::EnforcementBackend;
use probe_config::AgentConfig;
use probe_core::CapabilityMatrix;
use runtime::{ProviderRegistry, RuntimePlan};

use crate::{
    capture_registry::default_provider_registry,
    configured_enforcement::ConfiguredEnforcementError,
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
    ) -> Result<(RuntimePlan, Option<Box<dyn EnforcementBackend>>), ConfiguredEnforcementError>
    {
        let backend =
            select_enforcement_backend(self.connection_enforcement, self.transparent_interception)?;
        Ok((self.plan, backend))
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

fn select_enforcement_backend(
    connection: ConnectionEnforcementRuntime,
    transparent_interception: TransparentInterceptionRuntime,
) -> Result<Option<Box<dyn EnforcementBackend>>, ConfiguredEnforcementError> {
    select_single_enforcement_backend([
        connection.into_backend(),
        transparent_interception.into_backend(),
    ])
}

fn select_single_enforcement_backend(
    backends: impl IntoIterator<Item = Option<Box<dyn EnforcementBackend>>>,
) -> Result<Option<Box<dyn EnforcementBackend>>, ConfiguredEnforcementError> {
    let mut selected = None;
    for backend in backends.into_iter().flatten() {
        if selected.replace(backend).is_some() {
            return Err(ConfiguredEnforcementError::MultipleExecutableBackends);
        }
    }
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use enforcement::{EnforcementBackendDecision, EnforcementBackendRequest, EnforcementError};

    use super::*;

    #[test]
    fn multiple_executable_enforcement_backends_fail_closed() {
        let error = match select_single_enforcement_backend([
            Some(Box::new(RejectingBackend) as Box<dyn EnforcementBackend>),
            Some(Box::new(RejectingBackend) as Box<dyn EnforcementBackend>),
        ]) {
            Ok(_) => panic!("multiple executable surfaces must not be silently collapsed"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ConfiguredEnforcementError::MultipleExecutableBackends
        ));
    }

    struct RejectingBackend;

    impl EnforcementBackend for RejectingBackend {
        fn apply(
            &mut self,
            _request: EnforcementBackendRequest<'_>,
        ) -> Result<EnforcementBackendDecision, EnforcementError> {
            Ok(EnforcementBackendDecision::unsupported("not used"))
        }
    }
}
