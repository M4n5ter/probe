use std::{fs, path::Path};

use e2e_support::mitm_bridge;
use probe_config::{
    AgentConfig, CaptureSelection, EnforcementPolicyManifest, EnforcementPolicySourceConfig,
    PolicyConfig, TlsMaterialConfig, TlsMaterialKind, TransparentInterceptionMitmBackendConfig,
    TransparentInterceptionMitmBackendReadinessProbeConfig,
    TransparentInterceptionMitmClientTrustModeConfig,
    TransparentInterceptionMitmManagedProcessConfig,
    TransparentInterceptionMitmPlaintextBridgeModeConfig,
    TransparentInterceptionMitmPolicyHookModeConfig, TransparentInterceptionMitmProductProxyConfig,
    TransparentInterceptionMitmProductProxyUpstreamRouteConfig,
    TransparentInterceptionProxyModeConfig, TransparentInterceptionProxySelfBypassConfig,
    TransparentInterceptionStrategyConfig,
};
use probe_core::{
    Action, Direction, EnforcementMode, ProcessSelector, ProtectiveActionProfile, Selector,
    TrafficSelector,
};

use super::{
    backend::{MitmBackendConfig, MitmBridgeCase, MitmBridgeDirection},
    feed::{
        ENFORCEMENT_MANIFEST_ID, ENFORCEMENT_MANIFEST_VERSION, POLICY_ALERT_PREFIX,
        POLICY_HOOK_REASON_PREFIX, POLICY_ID, POLICY_VERSION, REQUEST_BODY_BYTES, REQUESTS,
        RESPONSE_BODY_BYTES, WRITE_CHUNKS,
    },
};
use crate::e2e::loopback::{Http1LoopbackFixtureConfig, PlainHttp1LoopbackFixtureConfig};

const AGENT_ID: &str = "e2e-mitm-bridge-agent";
const INTERFACE: &str = "any";

pub(super) struct AgentConfigInputs<'a> {
    pub(super) case: MitmBridgeCase,
    pub(super) config_path: &'a Path,
    pub(super) policy_path: &'a Path,
    pub(super) enforcement_manifest_path: Option<&'a Path>,
    pub(super) bridge_feed_path: &'a Path,
    pub(super) mitm_ca_certificate_path: &'a Path,
    pub(super) mitm_ca_private_key_path: &'a Path,
    pub(super) spool_path: &'a Path,
    pub(super) admin_socket_path: &'a Path,
    pub(super) capture_port: u16,
    pub(super) mitm_backend: &'a MitmBackendConfig,
    pub(super) policy_hook_endpoint: Option<String>,
    pub(super) proxy_port: u16,
    pub(super) intercept_port: u16,
}

pub(super) fn fixture_config() -> PlainHttp1LoopbackFixtureConfig {
    PlainHttp1LoopbackFixtureConfig {
        shared: Http1LoopbackFixtureConfig {
            listen_port: None,
            requests: REQUESTS,
            request_body_bytes: REQUEST_BODY_BYTES,
            response_body_bytes: RESPONSE_BODY_BYTES,
            write_chunks: WRITE_CHUNKS,
            connect_write_delay_ms: 0,
            post_exchange_delay_ms: 0,
        },
        accept_read_delay_ms: 0,
    }
}

pub(super) fn write_agent_config(
    inputs: AgentConfigInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: AGENT_ID.to_string(),
        config_version: inputs.case.case_name().to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(INTERFACE.to_string());
    config.capture.libpcap.bpf_filter = format!("tcp and port {}", inputs.capture_port);
    config.capture.libpcap.read_timeout_ms = 100;
    config.storage.path = inputs.spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = inputs.admin_socket_path.to_path_buf();
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        source: probe_config::PolicySourceConfig::LocalDirectory {
            path: inputs.policy_path.to_path_buf(),
        },
        enabled: true,
        selector: None,
    });
    config.enforcement.mode = EnforcementMode::Enforce;
    if let Some(path) = inputs.enforcement_manifest_path {
        config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
            path: path.to_path_buf(),
        };
    }
    config.enforcement.interception.strategy = interception_strategy(inputs.case.direction());
    config.enforcement.interception.proxy.mode = TransparentInterceptionProxyModeConfig::External;
    config.enforcement.interception.proxy.self_bypass = proxy_self_bypass(inputs.case.direction());
    config.enforcement.interception.proxy.listen_port = Some(inputs.proxy_port);
    config.enforcement.interception.selector = Some(interception_selector(
        inputs.case.direction(),
        inputs.intercept_port,
    ));
    config.enforcement.interception.mitm.backend = match inputs.mitm_backend {
        MitmBackendConfig::External { target } => {
            TransparentInterceptionMitmBackendConfig::external(external_mitm_readiness_probe(
                target.clone(),
            ))
        }
        MitmBackendConfig::ManagedProcess {
            target,
            program,
            args,
            ..
        } => TransparentInterceptionMitmBackendConfig::managed_process(
            mitm_readiness_probe(target.clone()),
            TransparentInterceptionMitmManagedProcessConfig {
                program: Some(program.clone()),
                args: args.clone(),
                working_dir: None,
            },
        ),
        MitmBackendConfig::ProductProxy {
            target,
            program,
            upstream_route,
        } => TransparentInterceptionMitmBackendConfig::product_proxy(
            mitm_readiness_probe(target.clone()),
            TransparentInterceptionMitmProductProxyConfig {
                program: Some(program.clone()),
                working_dir: None,
                upstream_routes: vec![TransparentInterceptionMitmProductProxyUpstreamRouteConfig {
                    host: upstream_route.route_host.clone(),
                    target: upstream_route.target.to_string(),
                }],
            },
        ),
    };
    config.enforcement.interception.mitm.plaintext_bridge.mode =
        TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
    config.enforcement.interception.mitm.plaintext_bridge.path =
        Some(inputs.bridge_feed_path.to_path_buf());
    config.enforcement.interception.mitm.plaintext_bridge.follow = Some(true);
    config.enforcement.interception.mitm.client_trust.mode =
        TransparentInterceptionMitmClientTrustModeConfig::OperatorManaged;
    config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
    config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
    if let Some(endpoint) = inputs.policy_hook_endpoint {
        config.enforcement.interception.mitm.policy_hook.mode =
            TransparentInterceptionMitmPolicyHookModeConfig::HttpJson;
        config.enforcement.interception.mitm.policy_hook.endpoint = Some(endpoint);
        config.enforcement.interception.mitm.policy_hook.timeout_ms = 1_000;
        config
            .enforcement
            .interception
            .mitm
            .policy_hook
            .max_response_bytes = 4096;
    }
    let mut tls_materials = vec![
        TlsMaterialConfig {
            id: Some("mitm-ca".to_string()),
            kind: TlsMaterialKind::MitmCaCertificate,
            path: inputs.mitm_ca_certificate_path.to_path_buf(),
        },
        TlsMaterialConfig {
            id: Some("mitm-ca-key".to_string()),
            kind: TlsMaterialKind::MitmCaPrivateKey,
            path: inputs.mitm_ca_private_key_path.to_path_buf(),
        },
    ];
    if let MitmBackendConfig::ProductProxy { upstream_route, .. } = inputs.mitm_backend {
        config
            .enforcement
            .interception
            .mitm
            .upstream_trust_anchor_refs = vec!["product-upstream-ca".to_string()];
        tls_materials.push(TlsMaterialConfig {
            id: Some("product-upstream-ca".to_string()),
            kind: TlsMaterialKind::MitmUpstreamTrustAnchor,
            path: upstream_route.certificate_path.clone(),
        });
    }
    config.tls.materials = tls_materials;
    fs::write(inputs.config_path, toml::to_string(&config)?)?;
    Ok(())
}

fn interception_strategy(direction: MitmBridgeDirection) -> TransparentInterceptionStrategyConfig {
    match direction {
        MitmBridgeDirection::Inbound => TransparentInterceptionStrategyConfig::InboundTproxyMitm,
        MitmBridgeDirection::Outbound => {
            TransparentInterceptionStrategyConfig::OutboundTransparentMitm
        }
    }
}

fn proxy_self_bypass(
    direction: MitmBridgeDirection,
) -> TransparentInterceptionProxySelfBypassConfig {
    match direction {
        MitmBridgeDirection::Inbound => TransparentInterceptionProxySelfBypassConfig::None,
        MitmBridgeDirection::Outbound => {
            TransparentInterceptionProxySelfBypassConfig::UsesReservedMark
        }
    }
}

fn interception_selector(direction: MitmBridgeDirection, port: u16) -> Selector {
    match direction {
        MitmBridgeDirection::Inbound => Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                local_ports: vec![port],
                directions: vec![Direction::Inbound],
                ..TrafficSelector::default()
            },
        ),
        MitmBridgeDirection::Outbound => Selector::term(
            ProcessSelector::default(),
            TrafficSelector {
                remote_ports: vec![port],
                directions: vec![Direction::Outbound],
                remote_addresses: vec!["127.0.0.1".to_string()],
                ..TrafficSelector::default()
            },
        ),
    }
}

pub(super) fn write_policy_bundle(path: &Path, case: MitmBridgeCase) -> Result<(), std::io::Error> {
    fs::create_dir_all(path)?;
    fs::write(
        path.join("manifest.toml"),
        format!(
            r#"
id = "{POLICY_ID}"
version = "{POLICY_VERSION}"
hooks = ["on_http_request_headers"]
"#
        ),
    )?;
    let protected_target = mitm_bridge::REQUEST_TARGET;
    let source = if case.spec().policy_hook.expects_delegated_decision() {
        format!(
            r#"
function on_http_request_headers(event)
  local target = event.kind.target or ""
  local alert = probe.emit_alert("{POLICY_ALERT_PREFIX}" .. target)
  if target ~= "{protected_target}" then
    return alert
  end
  return {{
    alert,
    probe.verdict({{
      action = "deny",
      scope = "request",
      reason = "{POLICY_HOOK_REASON_PREFIX}" .. target,
      confidence = 100,
    }}),
  }}
end
"#,
        )
    } else {
        format!(
            r#"
function on_http_request_headers(event)
  return probe.emit_alert("{POLICY_ALERT_PREFIX}" .. event.kind.target)
end
"#,
        )
    };
    fs::write(path.join("main.lua"), source)
}

pub(super) fn write_enforcement_manifest(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let manifest = EnforcementPolicyManifest {
        id: ENFORCEMENT_MANIFEST_ID.to_string(),
        version: ENFORCEMENT_MANIFEST_VERSION.to_string(),
        selector: None,
        protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
    };
    fs::write(path, toml::to_string(&manifest)?)?;
    Ok(())
}

fn mitm_readiness_probe(target: String) -> TransparentInterceptionMitmBackendReadinessProbeConfig {
    TransparentInterceptionMitmBackendReadinessProbeConfig {
        target: Some(target),
        ..TransparentInterceptionMitmBackendReadinessProbeConfig::default()
    }
}

fn external_mitm_readiness_probe(
    target: String,
) -> TransparentInterceptionMitmBackendReadinessProbeConfig {
    let mut probe = mitm_readiness_probe(target);
    probe.interval_ms = 100;
    probe.timeout_ms = 10;
    probe.failure_threshold = 1;
    probe
}
