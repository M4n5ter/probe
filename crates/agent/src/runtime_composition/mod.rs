use enforcement::EnforcementBackend;
use probe_config::AgentConfig;
use probe_core::CapabilityMatrix;
use runtime::{ProviderRegistry, RuntimePlan, TransparentInterceptionExecutionPlan};

use crate::{
    capture_registry::default_provider_registry,
    connection_enforcement::{self, ConnectionEnforcementRuntime},
    error::AgentError,
    l7_mitm::{self, L7MitmRuntime},
    transparent_interception::{self, TransparentInterceptionRuntime},
};

pub(crate) struct RuntimeComposition {
    plan: RuntimePlan,
    connection_enforcement: ConnectionEnforcementRuntime,
    l7_mitm: L7MitmRuntime,
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
        L7MitmRuntime,
        TransparentInterceptionRuntime,
    ) {
        (
            self.plan,
            self.connection_enforcement.into_backend(),
            self.l7_mitm,
            self.transparent_interception,
        )
    }
}

pub(crate) fn build_runtime_composition(
    config: AgentConfig,
) -> Result<RuntimeComposition, AgentError> {
    let (connection_enforcement, l7_mitm, transparent_interception) =
        execution_runtimes_for_config(&config);
    let registry = provider_registry_for_runtimes(
        &config,
        &connection_enforcement,
        &l7_mitm,
        &transparent_interception,
    );
    build_runtime_composition_from_registry(
        config,
        connection_enforcement,
        l7_mitm,
        transparent_interception,
        registry,
    )
}

fn build_runtime_composition_from_registry(
    config: AgentConfig,
    connection_enforcement: ConnectionEnforcementRuntime,
    l7_mitm: L7MitmRuntime,
    transparent_interception: TransparentInterceptionRuntime,
    registry: ProviderRegistry,
) -> Result<RuntimeComposition, AgentError> {
    let plan = RuntimePlan::build(config, &registry).map_err(AgentError::Runtime)?;
    Ok(RuntimeComposition {
        plan,
        connection_enforcement,
        l7_mitm,
        transparent_interception,
    })
}

#[cfg(test)]
pub(crate) fn build_runtime_composition_for_test(
    config: AgentConfig,
    capture_providers: Vec<runtime::CaptureProviderDescriptor>,
    platform: runtime::PlatformProbeResults,
) -> Result<RuntimeComposition, AgentError> {
    let (connection_enforcement, l7_mitm, transparent_interception) =
        execution_runtimes_for_config(&config);
    let registry = ProviderRegistry::with_platform_probes(capture_providers, platform);
    build_runtime_composition_from_registry(
        config,
        connection_enforcement,
        l7_mitm,
        transparent_interception,
        registry,
    )
}

pub(crate) fn capability_matrix_for_config(config: &AgentConfig) -> CapabilityMatrix {
    let (connection_enforcement, l7_mitm, transparent_interception) =
        execution_runtimes_for_config(config);
    provider_registry_for_runtimes(
        config,
        &connection_enforcement,
        &l7_mitm,
        &transparent_interception,
    )
    .capability_matrix()
}

fn execution_runtimes_for_config(
    config: &AgentConfig,
) -> (
    ConnectionEnforcementRuntime,
    L7MitmRuntime,
    TransparentInterceptionRuntime,
) {
    let transparent_interception_execution =
        TransparentInterceptionExecutionPlan::try_from_config(&config.enforcement.interception);
    let transparent_interception = match transparent_interception_execution {
        Ok(execution_plan) => transparent_interception::resolve(execution_plan),
        Err(error) => transparent_interception::unavailable_for_config_error(error.to_string()),
    };
    (
        connection_enforcement::resolve(config.enforcement.backend),
        l7_mitm::resolve(config),
        transparent_interception,
    )
}

fn provider_registry_for_runtimes(
    config: &AgentConfig,
    connection_enforcement: &ConnectionEnforcementRuntime,
    l7_mitm: &L7MitmRuntime,
    transparent_interception: &TransparentInterceptionRuntime,
) -> ProviderRegistry {
    default_provider_registry(
        config,
        connection_enforcement.capability(),
        l7_mitm.capability(),
        transparent_interception.capability(),
    )
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, TcpListener};

    use probe_config::{
        CaptureSelection, TlsMaterialConfig, TlsMaterialKind,
        TransparentInterceptionMitmBackendConfig,
        TransparentInterceptionMitmBackendReadinessProbeConfig,
        TransparentInterceptionMitmManagedProcessConfig,
        TransparentInterceptionMitmPlaintextBridgeModeConfig,
        TransparentInterceptionStrategyConfig,
    };
    use probe_core::{
        CapabilityKind, CapabilityState, Direction, EnforcementMode, ProcessSelector, RuntimeMode,
        Selector, TrafficSelector,
    };
    use runtime::{CaptureProviderBuilder, CaptureProviderDescriptor, PlatformProbeResults};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn default_composition_has_no_executable_enforcement_backend() {
        let composition = build_runtime_composition(AgentConfig::default())
            .expect("default composition should build");
        let (_plan, backend) = composition.into_enforcement_parts();

        assert!(backend.is_none());
    }

    #[test]
    fn outbound_transparent_proxy_requires_available_interception_capability() {
        let mut config = AgentConfig::default();
        config.capture.selection = CaptureSelection::Libpcap;
        config.enforcement.mode = EnforcementMode::Enforce;
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
        config.enforcement.interception.proxy.mode =
            probe_config::TransparentInterceptionProxyModeConfig::ManagedTcpRelay;
        config.enforcement.interception.proxy.listen_port = Some(15001);
        config.enforcement.interception.selector = Some(Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![443],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        ));
        let error = match build_runtime_composition_for_test(
            config,
            vec![CaptureProviderDescriptor::available(
                probe_config::CaptureBackend::Libpcap,
                CaptureProviderBuilder::Libpcap,
            )],
            test_platform_probes(),
        ) {
            Ok(_) => panic!("outbound transparent proxy should require executable capability"),
            Err(error) => error,
        };

        let message = error.to_string();
        assert!(message.contains("not configured"), "{message}");
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

    #[test]
    fn external_mitm_contract_reports_l7_mitm_available() -> Result<(), Box<dyn std::error::Error>>
    {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut config = AgentConfig::default();
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        let target = listener.local_addr()?;
        config.enforcement.interception.proxy.listen_port = Some(target.port());
        configure_external_mitm_backend(&mut config, target);

        let capabilities = capability_matrix_for_config(&config);
        let l7_mitm = capabilities
            .reported_state(CapabilityKind::L7Mitm)
            .expect("L7 MITM capability should be reported");

        assert_eq!(l7_mitm.mode, RuntimeMode::Available);
        assert!(
            l7_mitm
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("external selector-scoped"))
        );
        Ok(())
    }

    #[test]
    fn l7_mitm_capability_ignores_transparent_proxy_contract_errors()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut config = AgentConfig::default();
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm;
        config.enforcement.interception.proxy.mode =
            probe_config::TransparentInterceptionProxyModeConfig::ManagedTcpRelay;
        let target = listener.local_addr()?;
        config.enforcement.interception.proxy.listen_port = Some(target.port());
        configure_external_mitm_backend(&mut config, target);

        let capabilities = capability_matrix_for_config(&config);
        let l7_mitm = capabilities
            .reported_state(CapabilityKind::L7Mitm)
            .expect("L7 MITM capability should be reported");

        assert_eq!(l7_mitm.mode, RuntimeMode::Available);
        Ok(())
    }

    #[test]
    fn managed_process_mitm_contract_reports_l7_mitm_available()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut config = AgentConfig::default();
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        configure_managed_process_mitm_backend(&mut config)?;

        let capabilities = capability_matrix_for_config(&config);
        let l7_mitm = capabilities
            .reported_state(CapabilityKind::L7Mitm)
            .expect("L7 MITM capability should be reported");

        assert_eq!(l7_mitm.mode, RuntimeMode::Available);
        assert!(
            l7_mitm
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("agent-managed selector-scoped")),
            "{l7_mitm:?}"
        );
        Ok(())
    }

    #[test]
    fn missing_external_mitm_plaintext_bridge_openability_is_deferred_to_capture_preflight()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let mut config = AgentConfig::default();
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        let target = listener.local_addr()?;
        config.enforcement.interception.proxy.listen_port = Some(target.port());
        configure_external_mitm_backend(&mut config, target);
        config.enforcement.interception.mitm.plaintext_bridge.mode =
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
        config.enforcement.interception.mitm.plaintext_bridge.path = Some(missing_bridge_path()?);

        let capabilities = capability_matrix_for_config(&config);
        let l7_mitm = capabilities
            .reported_state(CapabilityKind::L7Mitm)
            .expect("L7 MITM capability should be reported");

        assert_eq!(l7_mitm.mode, RuntimeMode::Available);
        assert!(
            l7_mitm
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("external selector-scoped")),
            "{l7_mitm:?}"
        );
        Ok(())
    }

    #[test]
    fn invalid_external_mitm_contract_reports_l7_mitm_unavailable() {
        let mut config = AgentConfig::default();
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::external(
                TransparentInterceptionMitmBackendReadinessProbeConfig {
                    target: Some("127.0.0.1:15002".to_string()),
                    ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                },
            );
        config.enforcement.interception.mitm.ca_certificate_ref = Some("missing-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref =
            Some("missing-ca-key".to_string());

        let capabilities = capability_matrix_for_config(&config);
        let l7_mitm = capabilities
            .reported_state(CapabilityKind::L7Mitm)
            .expect("L7 MITM capability should be reported");

        assert_eq!(l7_mitm.mode, RuntimeMode::Unavailable);
        assert!(
            l7_mitm
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("missing-ca")),
            "{l7_mitm:?}"
        );
    }

    #[test]
    fn mitm_strategy_without_explicit_backend_reports_l7_mitm_unavailable() {
        let mut config = AgentConfig::default();
        config.enforcement.interception.strategy =
            TransparentInterceptionStrategyConfig::InboundTproxyMitm;
        config.enforcement.interception.proxy.listen_port = Some(15002);

        let capabilities = capability_matrix_for_config(&config);
        let l7_mitm = capabilities
            .reported_state(CapabilityKind::L7Mitm)
            .expect("L7 MITM capability should be reported");

        assert_eq!(l7_mitm.mode, RuntimeMode::Unavailable);
        assert!(l7_mitm.reason.as_deref().is_some_and(|reason| {
            reason.contains("backend.mode = \"external\" or \"managed_process\"")
        }));
    }

    fn test_platform_probes() -> PlatformProbeResults {
        PlatformProbeResults {
            procfs_socket: Vec::new(),
            connection_enforcement: CapabilityState::unavailable(
                CapabilityKind::ConnectionEnforcement,
                "not configured",
            ),
            transparent_interception: CapabilityState::unavailable(
                CapabilityKind::TransparentInterception,
                "not configured",
            ),
            transparent_process_classifier:
                PlatformProbeResults::default_transparent_process_classifier(),
            transparent_flow_classifier: PlatformProbeResults::default_transparent_flow_classifier(
            ),
            l7_mitm: CapabilityState::unavailable(CapabilityKind::L7Mitm, "not configured"),
            libssl_uprobe: CapabilityState::unavailable(
                CapabilityKind::LibsslUprobe,
                "not configured",
            ),
        }
    }

    fn configure_external_mitm_backend(config: &mut AgentConfig, target: SocketAddr) {
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::external(
                TransparentInterceptionMitmBackendReadinessProbeConfig {
                    target: Some(target.to_string()),
                    ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
                },
            );
        configure_mitm_materials(config);
    }

    fn configure_mitm_materials(config: &mut AgentConfig) {
        config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
        config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
        config.tls.materials = vec![
            TlsMaterialConfig {
                id: Some("mitm-ca".to_string()),
                kind: TlsMaterialKind::MitmCaCertificate,
                path: "/etc/traffic-probe/mitm-ca.pem".into(),
            },
            TlsMaterialConfig {
                id: Some("mitm-ca-key".to_string()),
                kind: TlsMaterialKind::MitmCaPrivateKey,
                path: "/etc/traffic-probe/mitm-ca.key".into(),
            },
        ];
    }

    fn configure_managed_process_mitm_backend(
        config: &mut AgentConfig,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let target: SocketAddr = "127.0.0.1:15002"
            .parse()
            .expect("test MITM target should parse");
        let readiness_probe = TransparentInterceptionMitmBackendReadinessProbeConfig {
            target: Some(target.to_string()),
            ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
        };
        let process = TransparentInterceptionMitmManagedProcessConfig {
            program: Some(std::env::current_exe()?),
            args: vec!["--listen".to_string(), "127.0.0.1:15002".to_string()],
            working_dir: None,
        };
        config.enforcement.interception.mitm.backend =
            TransparentInterceptionMitmBackendConfig::managed_process(readiness_probe, process);
        configure_mitm_materials(config);
        Ok(())
    }

    fn missing_bridge_path() -> Result<std::path::PathBuf, std::io::Error> {
        Ok(tempdir()?.path().join("missing-mitm-bridge.jsonl"))
    }
}
