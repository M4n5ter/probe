use std::{fs, path::Path};

use probe_config::{
    AgentConfig, CaptureSelection, PolicyConfig, TlsMaterialConfig, TlsMaterialKind,
    TransparentInterceptionMitmBackendConfig,
    TransparentInterceptionMitmBackendReadinessProbeConfig,
    TransparentInterceptionMitmManagedProcessConfig,
    TransparentInterceptionMitmPlaintextBridgeModeConfig, TransparentInterceptionProxyModeConfig,
    TransparentInterceptionStrategyConfig,
};
use probe_core::{Direction, EnforcementMode, ProcessSelector, Selector, TrafficSelector};

use super::{
    backend::{MitmBackendCase, MitmBackendConfig},
    feed::{
        POLICY_ALERT_PREFIX, POLICY_ID, POLICY_VERSION, REQUEST_BODY_BYTES, REQUESTS,
        RESPONSE_BODY_BYTES, WRITE_CHUNKS,
    },
};
use crate::e2e::loopback::{Http1LoopbackFixtureConfig, PlainHttp1LoopbackFixtureConfig};

const AGENT_ID: &str = "e2e-mitm-bridge-agent";
const INTERFACE: &str = "any";

pub(super) struct AgentConfigInputs<'a> {
    pub(super) case: MitmBackendCase,
    pub(super) config_path: &'a Path,
    pub(super) policy_path: &'a Path,
    pub(super) bridge_feed_path: &'a Path,
    pub(super) spool_path: &'a Path,
    pub(super) admin_socket_path: &'a Path,
    pub(super) capture_port: u16,
    pub(super) mitm_backend: &'a MitmBackendConfig,
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
    config.enforcement.interception.strategy =
        TransparentInterceptionStrategyConfig::InboundTproxyMitm;
    config.enforcement.interception.proxy.mode = TransparentInterceptionProxyModeConfig::External;
    config.enforcement.interception.proxy.listen_port = Some(inputs.proxy_port);
    config.enforcement.interception.selector = Some(Selector::term(
        ProcessSelector::default(),
        TrafficSelector {
            local_ports: vec![inputs.intercept_port],
            directions: vec![Direction::Inbound],
            ..TrafficSelector::default()
        },
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
    };
    config.enforcement.interception.mitm.plaintext_bridge.mode =
        TransparentInterceptionMitmPlaintextBridgeModeConfig::CaptureEventFeed;
    config.enforcement.interception.mitm.plaintext_bridge.path =
        Some(inputs.bridge_feed_path.to_path_buf());
    config.enforcement.interception.mitm.plaintext_bridge.follow = Some(true);
    config.enforcement.interception.mitm.ca_certificate_ref = Some("mitm-ca".to_string());
    config.enforcement.interception.mitm.ca_private_key_ref = Some("mitm-ca-key".to_string());
    config.tls.materials = vec![
        TlsMaterialConfig {
            id: Some("mitm-ca".to_string()),
            kind: TlsMaterialKind::MitmCaCertificate,
            path: inputs.config_path.with_file_name("mitm-ca.pem"),
        },
        TlsMaterialConfig {
            id: Some("mitm-ca-key".to_string()),
            kind: TlsMaterialKind::MitmCaPrivateKey,
            path: inputs.config_path.with_file_name("mitm-ca.key"),
        },
    ];
    fs::write(inputs.config_path, toml::to_string(&config)?)?;
    Ok(())
}

pub(super) fn write_policy_bundle(path: &Path) -> Result<(), std::io::Error> {
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
    fs::write(
        path.join("main.lua"),
        format!(
            r#"
function on_http_request_headers(event)
  return probe.emit_alert("{POLICY_ALERT_PREFIX}" .. event.kind.target)
end
"#,
        ),
    )
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
