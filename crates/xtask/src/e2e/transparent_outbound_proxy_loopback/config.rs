use std::{collections::BTreeMap, fs, path::Path};

use probe_config::{
    AgentConfig, CaptureSelection, CompressionCodecName, EnforcementPolicyManifest,
    EnforcementPolicySourceConfig, ExportFailureBackoffConfig, ExportWorkerScheduleConfig,
    ExporterConfig, ExporterTransportConfig, PolicyConfig, TransparentInterceptionProxyConfig,
    TransparentInterceptionProxyModeConfig, TransparentInterceptionStrategyConfig,
};
use probe_core::{
    Action, Direction, EnforcementMode, ProcessSelector, ProtectiveActionProfile, Selector,
    TrafficSelector,
};

use super::{LOOPBACK_ADDR, OutboundProxyE2eCase, OutboundProxyE2eMode, PROXY_PORT, UPSTREAM_PORT};

const COLLECTOR_SINK: &str = "collector";
const POLICY_ID: &str = "outbound-proxy-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const ENFORCEMENT_MANIFEST_ID: &str = "e2e-transparent-outbound-enforcement";
const ENFORCEMENT_MANIFEST_VERSION: &str = "e2e";

pub(super) enum PolicySourceFixture<'a> {
    LocalDirectory(&'a Path),
    RemoteBundle { endpoint: String, listen_port: u16 },
}

pub(super) struct AgentConfigInputs<'a> {
    pub(super) path: &'a Path,
    pub(super) spool_path: &'a Path,
    pub(super) admin_socket_path: &'a Path,
    pub(super) enforcement_manifest_path: &'a Path,
    pub(super) policy_source: PolicySourceFixture<'a>,
    pub(super) webhook_endpoint: String,
    pub(super) remote_ports: &'a [u16],
    pub(super) case: OutboundProxyE2eCase,
}

pub(super) fn write_agent_config(
    inputs: AgentConfigInputs<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: inputs.case.agent_id.to_string(),
        config_version: inputs.case.case_name.to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some("lo".to_string());
    config.capture.libpcap.bpf_filter =
        format!("tcp and (port {UPSTREAM_PORT} or port {PROXY_PORT})");
    config.capture.libpcap.read_timeout_ms = 100;
    config.storage.path = inputs.spool_path.to_path_buf();
    config.export.worker.enabled = true;
    config.export.worker.schedule = ExportWorkerScheduleConfig::FixedIntervalBounded {
        interval_ms: 100,
        batches_per_sink_per_tick: 1,
        sink_timeout_ms: 5_000,
        failure_backoff: ExportFailureBackoffConfig {
            initial_ms: 5_000,
            max_ms: 5_000,
            multiplier: 1,
        },
    };
    config.exporters.push(ExporterConfig {
        id: COLLECTOR_SINK.to_string(),
        transport: ExporterTransportConfig::Webhook {
            endpoint: inputs.webhook_endpoint,
            headers: BTreeMap::from([(
                "x-traffic-probe-e2e".to_string(),
                inputs.case.header_value.to_string(),
            )]),
            tls: Default::default(),
        },
        codec: CompressionCodecName::None,
        worker: Default::default(),
    });
    config.admin.enabled = true;
    config.admin.socket_path = inputs.admin_socket_path.to_path_buf();
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        source: match inputs.policy_source {
            PolicySourceFixture::LocalDirectory(path) => {
                probe_config::PolicySourceConfig::LocalDirectory {
                    path: path.to_path_buf(),
                }
            }
            PolicySourceFixture::RemoteBundle { endpoint, .. } => {
                probe_config::PolicySourceConfig::RemoteBundle {
                    endpoint,
                    max_body_bytes: Some(1024 * 1024),
                }
            }
        },
        enabled: true,
        selector: None,
        ..PolicyConfig::default()
    });
    config.enforcement.mode = EnforcementMode::Enforce;
    let selector = Selector::term(
        process_selector(inputs.case.proxy_mode),
        TrafficSelector {
            remote_ports: inputs.remote_ports.to_vec(),
            directions: vec![Direction::Outbound],
            remote_addresses: vec![LOOPBACK_ADDR.to_string()],
            ..TrafficSelector::default()
        },
    );
    super::super::enforcement_manifest::write_enforcement_policy_manifest(
        inputs.enforcement_manifest_path,
        &EnforcementPolicyManifest {
            id: ENFORCEMENT_MANIFEST_ID.to_string(),
            version: ENFORCEMENT_MANIFEST_VERSION.to_string(),
            selectors: Default::default(),
            selector: None,
            protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
        },
    )?;
    config.enforcement.policy.source = EnforcementPolicySourceConfig::File {
        path: inputs.enforcement_manifest_path.to_path_buf(),
    };
    config.enforcement.interception.strategy =
        TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
    config.enforcement.interception.proxy = match inputs.case.proxy_mode {
        OutboundProxyE2eMode::ManagedRelay | OutboundProxyE2eMode::OwnerScopedManagedRelay => {
            TransparentInterceptionProxyConfig {
                mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
                listen_port: Some(PROXY_PORT),
                ..TransparentInterceptionProxyConfig::default()
            }
        }
        OutboundProxyE2eMode::ExternalProxy => TransparentInterceptionProxyConfig {
            mode: TransparentInterceptionProxyModeConfig::External,
            self_bypass:
                probe_config::TransparentInterceptionProxySelfBypassConfig::UsesReservedMark,
            listen_port: Some(PROXY_PORT),
            ..TransparentInterceptionProxyConfig::default()
        },
    };
    config.enforcement.interception.selector = Some(selector);
    fs::write(inputs.path, toml::to_string(&config)?)?;
    Ok(())
}

pub(super) fn redirected_remote_ports(
    mode: OutboundProxyE2eMode,
    webhook_port: u16,
    policy_source: &PolicySourceFixture<'_>,
) -> Vec<u16> {
    match mode {
        OutboundProxyE2eMode::OwnerScopedManagedRelay => vec![UPSTREAM_PORT],
        OutboundProxyE2eMode::ManagedRelay | OutboundProxyE2eMode::ExternalProxy => {
            let mut ports = vec![UPSTREAM_PORT, webhook_port];
            if let PolicySourceFixture::RemoteBundle { listen_port, .. } = policy_source {
                ports.push(*listen_port);
            }
            ports
        }
    }
}

fn process_selector(mode: OutboundProxyE2eMode) -> ProcessSelector {
    match mode {
        OutboundProxyE2eMode::OwnerScopedManagedRelay => ProcessSelector {
            uids: vec![super::OWNER_SCOPED_CLIENT_UID],
            gids: vec![super::OWNER_SCOPED_CLIENT_GID],
            ..ProcessSelector::default()
        },
        OutboundProxyE2eMode::ManagedRelay | OutboundProxyE2eMode::ExternalProxy => {
            ProcessSelector::default()
        }
    }
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
    fs::write(path.join("main.lua"), policy_source())
}

pub(super) fn remote_policy_bundle_document() -> String {
    format!(
        r#"source = {source:?}

[manifest]
id = "{POLICY_ID}"
version = "{POLICY_VERSION}"
hooks = ["on_http_request_headers"]
"#,
        source = policy_source()
    )
}

fn policy_source() -> &'static str {
    r#"
function on_http_request_headers(event)
  local target = event.kind.target or ""
  if target == "/transparent-outbound-proxy-e2e" then
    return probe.emit_alert("transparent outbound proxy observed " .. target)
  end
end
"#
}
