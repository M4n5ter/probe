use std::path::PathBuf;

use interception::{
    TransparentInterceptionSetupDirection, TransparentInterceptionSetupPlan,
    TransparentInterceptionSetupProjectionError,
};
use probe_config::{
    AgentConfig, CaptureSelection, ConnectionEnforcementBackendConfig,
    EnforcementPolicySourceConfig, TlsMaterialConfig, TlsMaterialKind,
    TransparentInterceptionMitmBackendConfig,
    TransparentInterceptionMitmBackendReadinessProbeConfig,
    TransparentInterceptionMitmClientTrustModeConfig,
    TransparentInterceptionMitmPlaintextBridgeModeConfig,
    TransparentInterceptionMitmPolicyHookConfig, TransparentInterceptionMitmPolicyHookModeConfig,
    TransparentInterceptionMitmProductProxyConfig,
    TransparentInterceptionMitmProductProxyUpstreamDiscoveryConfig,
    TransparentInterceptionProxyModeConfig, TransparentInterceptionProxySelfBypassConfig,
    TransparentInterceptionStrategyConfig,
};
use probe_core::{Direction, EnforcementMode, ProcessSelector, Selector, TrafficSelector};

use super::local_profile::LocalMitmProfile;

pub(super) const MITM_CA_CERTIFICATE_ID: &str = "mitm-ca";
pub(super) const MITM_CA_PRIVATE_KEY_ID: &str = "mitm-ca-key";
pub(super) const DEFAULT_OUTBOUND_MITM_REMOTE_PORTS: [u16; 2] = [80, 443];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MitmQuickSetupDirection {
    Outbound,
    Inbound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MitmQuickSetupOutcome {
    Changed {
        direction: MitmQuickSetupDirection,
        warnings: Vec<MitmQuickSetupWarning>,
    },
    Rejected(MitmQuickSetupWarning),
    MissingProcessSelector,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum MitmQuickSetupWarning {
    MissingProxyExecutable { path: PathBuf },
    UnsupportedOutboundProcessSelector { reason: String },
}

pub(crate) fn apply_mitm_quick_setup(
    config: &mut AgentConfig,
    direction: MitmQuickSetupDirection,
    selected_process_selector: Option<Selector>,
) -> MitmQuickSetupOutcome {
    apply_mitm_quick_setup_with_profile(
        config,
        direction,
        selected_process_selector,
        &LocalMitmProfile::default(),
    )
}

pub(crate) fn apply_mitm_quick_setup_with_profile(
    config: &mut AgentConfig,
    direction: MitmQuickSetupDirection,
    selected_process_selector: Option<Selector>,
    profile: &LocalMitmProfile,
) -> MitmQuickSetupOutcome {
    let Some(selector) = selected_process_selector else {
        return MitmQuickSetupOutcome::MissingProcessSelector;
    };
    let selector = direction.scoped_selector(selector);
    if direction == MitmQuickSetupDirection::Outbound
        && let Some(reason) = outbound_process_selector_projection_blocker(&selector)
    {
        return MitmQuickSetupOutcome::Rejected(
            MitmQuickSetupWarning::UnsupportedOutboundProcessSelector { reason },
        );
    }

    config.capture.selection = CaptureSelection::Auto;
    config.enforcement.mode = EnforcementMode::Enforce;
    config.enforcement.backend = ConnectionEnforcementBackendConfig::None;
    config.enforcement.selector = Some(selector.clone());
    config.enforcement.interception.strategy = direction.strategy();
    config.enforcement.interception.selector = Some(selector);
    config.enforcement.interception.proxy.mode = TransparentInterceptionProxyModeConfig::External;
    config.enforcement.interception.proxy.self_bypass = direction.self_bypass();
    config.enforcement.interception.proxy.listen_port = Some(profile.proxy_listen_port);

    ensure_default_enforcement_policy_source(config, profile);
    configure_product_mitm_proxy(config, profile);
    upsert_default_mitm_tls_materials(config, profile);

    let warnings = quick_setup_warnings(profile);
    MitmQuickSetupOutcome::Changed {
        direction,
        warnings,
    }
}

fn outbound_process_selector_projection_blocker(selector: &Selector) -> Option<String> {
    match TransparentInterceptionSetupPlan::from_selector(
        Some(selector),
        TransparentInterceptionSetupDirection::Outbound,
    ) {
        Ok(TransparentInterceptionSetupPlan::RequiresProcessClassifier { reason, .. }) => {
            Some(reason)
        }
        Ok(
            TransparentInterceptionSetupPlan::HostRules(_)
            | TransparentInterceptionSetupPlan::RequiresFlowClassifier { .. },
        ) => None,
        Err(TransparentInterceptionSetupProjectionError::UnconstrainedSelector) => {
            Some("selected process scope does not project to outbound host rules".to_string())
        }
        Err(error) => Some(error.to_string()),
    }
}

fn quick_setup_warnings(profile: &LocalMitmProfile) -> Vec<MitmQuickSetupWarning> {
    if profile.proxy_program_is_executable() {
        Vec::new()
    } else {
        vec![MitmQuickSetupWarning::MissingProxyExecutable {
            path: profile.proxy_program.clone(),
        }]
    }
}

impl MitmQuickSetupDirection {
    fn scoped_selector(self, selector: Selector) -> Selector {
        match self {
            Self::Outbound => selector_with_default_outbound_mitm_traffic(selector),
            Self::Inbound => selector,
        }
    }

    fn strategy(self) -> TransparentInterceptionStrategyConfig {
        match self {
            Self::Outbound => TransparentInterceptionStrategyConfig::OutboundTransparentMitm,
            Self::Inbound => TransparentInterceptionStrategyConfig::InboundTproxyMitm,
        }
    }

    fn self_bypass(self) -> TransparentInterceptionProxySelfBypassConfig {
        match self {
            Self::Outbound => TransparentInterceptionProxySelfBypassConfig::UsesReservedMark,
            Self::Inbound => TransparentInterceptionProxySelfBypassConfig::None,
        }
    }

    pub(crate) fn status_message(self) -> &'static str {
        match self {
            Self::Outbound => "Outbound MITM capture configured for selected process",
            Self::Inbound => "Inbound MITM capture configured for selected process",
        }
    }
}

fn selector_with_default_outbound_mitm_traffic(selector: Selector) -> Selector {
    match selector {
        Selector::Match { mut term } => {
            add_default_outbound_mitm_traffic(&mut term.traffic);
            Selector::Match { term }
        }
        Selector::All { mut selectors } => {
            selectors.push(default_outbound_mitm_traffic_selector());
            Selector::All { selectors }
        }
        selector => Selector::All {
            selectors: vec![selector, default_outbound_mitm_traffic_selector()],
        },
    }
}

fn add_default_outbound_mitm_traffic(traffic: &mut TrafficSelector) {
    if traffic.remote_ports.is_empty() {
        traffic.remote_ports = DEFAULT_OUTBOUND_MITM_REMOTE_PORTS.to_vec();
    }
    if traffic.directions.is_empty() {
        traffic.directions = vec![Direction::Outbound];
    }
}

fn default_outbound_mitm_traffic_selector() -> Selector {
    Selector::term(
        ProcessSelector::default(),
        TrafficSelector {
            remote_ports: DEFAULT_OUTBOUND_MITM_REMOTE_PORTS.to_vec(),
            directions: vec![Direction::Outbound],
            ..TrafficSelector::default()
        },
    )
}

fn ensure_default_enforcement_policy_source(config: &mut AgentConfig, profile: &LocalMitmProfile) {
    if !matches!(
        config.enforcement.policy.source,
        EnforcementPolicySourceConfig::None
    ) {
        return;
    }
    config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
        path: profile.enforcement_policy_file.clone(),
    };
    config.enforcement.policy.reload.watch_local_manifest = true;
    config.enforcement.policy.reload.poll_remote_manifest = false;
}

fn configure_product_mitm_proxy(config: &mut AgentConfig, profile: &LocalMitmProfile) {
    let readiness_probe = TransparentInterceptionMitmBackendReadinessProbeConfig {
        target: Some(profile.readiness_target()),
        ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
    };
    let process = TransparentInterceptionMitmProductProxyConfig {
        program: Some(profile.proxy_program.clone()),
        working_dir: None,
        application_protocols: None,
        upstream_discovery: TransparentInterceptionMitmProductProxyUpstreamDiscoveryConfig::default(
        ),
        upstream_routes: Vec::new(),
    };

    let mitm = &mut config.enforcement.interception.mitm;
    mitm.backend =
        TransparentInterceptionMitmBackendConfig::product_proxy(readiness_probe, process);
    mitm.client_trust.mode = TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged;
    mitm.plaintext_bridge.mode =
        TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
    mitm.plaintext_bridge.path = Some(profile.plaintext_feed.clone());
    mitm.plaintext_bridge.follow = Some(true);
    mitm.policy_hook = TransparentInterceptionMitmPolicyHookConfig {
        mode: TransparentInterceptionMitmPolicyHookModeConfig::HttpJson,
        endpoint: Some(profile.policy_hook_endpoint()),
        ..TransparentInterceptionMitmPolicyHookConfig::default()
    };
    mitm.ca_certificate_ref = Some(MITM_CA_CERTIFICATE_ID.to_string());
    mitm.ca_private_key_ref = Some(MITM_CA_PRIVATE_KEY_ID.to_string());
    mitm.leaf_certificate_chain_refs.clear();
    mitm.leaf_private_key_ref = None;
}

fn upsert_default_mitm_tls_materials(config: &mut AgentConfig, profile: &LocalMitmProfile) {
    if !config
        .tls
        .material_store
        .filesystem
        .allowed_roots
        .iter()
        .any(|root| root == &profile.tls_root)
    {
        config
            .tls
            .material_store
            .filesystem
            .allowed_roots
            .push(profile.tls_root.clone());
    }
    upsert_tls_material(
        &mut config.tls.materials,
        MITM_CA_CERTIFICATE_ID,
        TlsMaterialKind::MitmCaCertificate,
        profile.ca_certificate.clone(),
    );
    upsert_tls_material(
        &mut config.tls.materials,
        MITM_CA_PRIVATE_KEY_ID,
        TlsMaterialKind::MitmCaPrivateKey,
        profile.ca_private_key.clone(),
    );
}

fn upsert_tls_material(
    materials: &mut Vec<TlsMaterialConfig>,
    id: &'static str,
    kind: TlsMaterialKind,
    default_path: PathBuf,
) {
    if let Some(material) = materials
        .iter_mut()
        .find(|material| material.id.as_deref() == Some(id))
    {
        material.kind = kind;
        if material.path.as_os_str().is_empty() {
            material.path = default_path;
        }
        return;
    }
    materials.push(TlsMaterialConfig {
        id: Some(id.to_string()),
        kind,
        path: default_path,
    });
}

#[cfg(test)]
mod tests {
    use probe_config::{
        TransparentInterceptionMitmBackendConfig, TransparentInterceptionMitmClientTrustModeConfig,
        TransparentInterceptionMitmPlaintextBridgeModeConfig,
        TransparentInterceptionMitmPolicyHookModeConfig,
    };
    use probe_core::Selector;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn outbound_mitm_quick_setup_configures_scoped_product_proxy_capture() {
        let temp = TempDir::new().expect("temp dir");
        let profile = LocalMitmProfile::with_root(temp.path());
        let mut config = AgentConfig::default();
        let selector = uid_selector(1000);

        let outcome = apply_mitm_quick_setup_with_profile(
            &mut config,
            MitmQuickSetupDirection::Outbound,
            Some(selector),
            &profile,
        );

        assert_eq!(
            outcome,
            MitmQuickSetupOutcome::Changed {
                direction: MitmQuickSetupDirection::Outbound,
                warnings: vec![MitmQuickSetupWarning::MissingProxyExecutable {
                    path: profile.proxy_program.clone(),
                }],
            }
        );
        assert_eq!(config.capture.selection, CaptureSelection::Auto);
        assert_eq!(config.enforcement.mode, EnforcementMode::Enforce);
        assert!(matches!(
            config.enforcement.policy.source,
            EnforcementPolicySourceConfig::File { .. }
        ));
        assert!(config.enforcement.policy.reload.watch_local_manifest);
        assert_eq!(
            config.enforcement.backend,
            ConnectionEnforcementBackendConfig::None
        );
        assert_eq!(
            config.enforcement.selector,
            config.enforcement.interception.selector
        );
        assert_eq!(
            config.enforcement.interception.strategy,
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm
        );
        assert_eq!(
            config.enforcement.interception.proxy.self_bypass,
            TransparentInterceptionProxySelfBypassConfig::UsesReservedMark
        );
        assert_outbound_mitm_uid_selector(
            config
                .enforcement
                .interception
                .selector
                .as_ref()
                .expect("outbound MITM selector should be configured"),
            1000,
        );
        assert!(
            config
                .tls
                .material_store
                .filesystem
                .allowed_roots
                .contains(&profile.tls_root)
        );
        assert_product_mitm_defaults(&config, &profile);
    }

    #[test]
    fn outbound_mitm_quick_setup_rejects_non_projectable_process_selector() {
        let temp = TempDir::new().expect("temp dir");
        let profile = LocalMitmProfile::with_root(temp.path());
        let mut config = AgentConfig::default();
        let selector = Selector::term(
            probe_core::ProcessSelector {
                exe_path_globs: vec!["/usr/bin/curl".to_string()],
                ..probe_core::ProcessSelector::default()
            },
            probe_core::TrafficSelector::default(),
        );

        let outcome = apply_mitm_quick_setup_with_profile(
            &mut config,
            MitmQuickSetupDirection::Outbound,
            Some(selector),
            &profile,
        );

        assert!(matches!(
            outcome,
            MitmQuickSetupOutcome::Rejected(
                MitmQuickSetupWarning::UnsupportedOutboundProcessSelector { .. }
            )
        ));
        assert_eq!(config, AgentConfig::default());
    }

    #[test]
    fn inbound_mitm_quick_setup_uses_inbound_strategy_without_self_bypass_mark() {
        let temp = TempDir::new().expect("temp dir");
        let profile = LocalMitmProfile::with_root(temp.path());
        let mut config = AgentConfig::default();

        let outcome = apply_mitm_quick_setup_with_profile(
            &mut config,
            MitmQuickSetupDirection::Inbound,
            Some(Selector::default()),
            &profile,
        );

        assert!(matches!(
            outcome,
            MitmQuickSetupOutcome::Changed {
                direction: MitmQuickSetupDirection::Inbound,
                warnings,
                ..
            } if warnings == vec![MitmQuickSetupWarning::MissingProxyExecutable {
                path: profile.proxy_program.clone(),
            }]
        ));
        assert_eq!(
            config.enforcement.interception.strategy,
            TransparentInterceptionStrategyConfig::InboundTproxyMitm
        );
        assert_eq!(
            config.enforcement.interception.proxy.self_bypass,
            TransparentInterceptionProxySelfBypassConfig::None
        );
        assert_product_mitm_defaults(&config, &profile);
    }

    #[test]
    fn mitm_quick_setup_reports_available_proxy_program() {
        let temp = TempDir::new().expect("temp dir");
        let profile = LocalMitmProfile::with_root(temp.path());
        std::fs::create_dir_all(profile.proxy_program.parent().expect("proxy parent"))
            .expect("create proxy parent");
        std::fs::write(&profile.proxy_program, b"proxy").expect("create proxy binary placeholder");
        make_executable(&profile.proxy_program);
        let mut config = AgentConfig::default();

        let outcome = apply_mitm_quick_setup_with_profile(
            &mut config,
            MitmQuickSetupDirection::Inbound,
            Some(Selector::default()),
            &profile,
        );

        assert_eq!(
            outcome,
            MitmQuickSetupOutcome::Changed {
                direction: MitmQuickSetupDirection::Inbound,
                warnings: Vec::new(),
            }
        );
    }

    #[test]
    fn mitm_quick_setup_requires_selected_process_selector() {
        let mut config = AgentConfig::default();

        let outcome = apply_mitm_quick_setup(&mut config, MitmQuickSetupDirection::Outbound, None);

        assert_eq!(outcome, MitmQuickSetupOutcome::MissingProcessSelector);
        assert_eq!(config, AgentConfig::default());
    }

    fn assert_product_mitm_defaults(config: &AgentConfig, profile: &LocalMitmProfile) {
        assert_eq!(
            config.enforcement.interception.proxy.listen_port,
            Some(profile.proxy_listen_port)
        );
        assert!(matches!(
            config.enforcement.interception.mitm.backend,
            TransparentInterceptionMitmBackendConfig::ProductProxy { .. }
        ));
        assert_eq!(
            config.enforcement.interception.mitm.client_trust.mode,
            TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged
        );
        assert_eq!(
            config.enforcement.interception.mitm.plaintext_bridge.mode,
            TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed
        );
        assert_eq!(
            config.enforcement.interception.mitm.plaintext_bridge.path,
            Some(profile.plaintext_feed.clone())
        );
        assert_eq!(
            config.enforcement.interception.mitm.policy_hook.mode,
            TransparentInterceptionMitmPolicyHookModeConfig::HttpJson
        );
        assert_eq!(
            config
                .enforcement
                .interception
                .mitm
                .ca_certificate_ref
                .as_deref(),
            Some(MITM_CA_CERTIFICATE_ID)
        );
        assert_eq!(
            config
                .enforcement
                .interception
                .mitm
                .ca_private_key_ref
                .as_deref(),
            Some(MITM_CA_PRIVATE_KEY_ID)
        );
        assert!(config.tls.materials.iter().any(|material| {
            material.id.as_deref() == Some(MITM_CA_CERTIFICATE_ID)
                && material.kind == TlsMaterialKind::MitmCaCertificate
                && material.path == profile.ca_certificate
        }));
        assert!(config.tls.materials.iter().any(|material| {
            material.id.as_deref() == Some(MITM_CA_PRIVATE_KEY_ID)
                && material.kind == TlsMaterialKind::MitmCaPrivateKey
                && material.path == profile.ca_private_key
        }));
    }

    fn uid_selector(uid: u32) -> Selector {
        Selector::term(
            probe_core::ProcessSelector {
                uids: vec![uid],
                ..probe_core::ProcessSelector::default()
            },
            probe_core::TrafficSelector::default(),
        )
    }

    fn assert_outbound_mitm_uid_selector(selector: &Selector, uid: u32) {
        let Selector::Match { term } = selector else {
            panic!("outbound MITM selector should be a match selector");
        };
        assert_eq!(term.process.uids, [uid]);
        assert_eq!(
            term.traffic.remote_ports,
            DEFAULT_OUTBOUND_MITM_REMOTE_PORTS
        );
        assert_eq!(term.traffic.directions, [Direction::Outbound]);
    }

    fn make_executable(path: &std::path::Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mut permissions = std::fs::metadata(path).expect("metadata").permissions();
            permissions.set_mode(0o700);
            std::fs::set_permissions(path, permissions).expect("set executable");
        }
    }
}
