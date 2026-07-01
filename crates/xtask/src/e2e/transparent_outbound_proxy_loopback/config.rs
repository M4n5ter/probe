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

use super::FLOW_CLASSIFIER_REJECTED_PORT;
use super::{
    LOOPBACK_ADDR, OutboundProxyE2eCase, OutboundProxyMode, OutboundProxyScenario, PROXY_PORT,
    UPSTREAM_PORT,
};

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
    pub(super) redirect_ports: &'a [u16],
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
    config.capture.libpcap.bpf_filter = capture_bpf_filter(inputs.case);
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
    let selector = interception_selector(inputs.case, inputs.redirect_ports);
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
        OutboundProxyMode::ManagedRelay => TransparentInterceptionProxyConfig {
            mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
            listen_port: Some(PROXY_PORT),
            ..TransparentInterceptionProxyConfig::default()
        },
        OutboundProxyMode::ExternalProxy => TransparentInterceptionProxyConfig {
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

fn capture_bpf_filter(case: OutboundProxyE2eCase) -> String {
    let mut ports = capture_ports(case);
    ports.push(PROXY_PORT);
    ports.sort_unstable();
    ports.dedup();
    format!(
        "tcp and ({})",
        ports
            .into_iter()
            .map(|port| format!("port {port}"))
            .collect::<Vec<_>>()
            .join(" or ")
    )
}

fn capture_ports(case: OutboundProxyE2eCase) -> Vec<u16> {
    if case.is_flow_classified() {
        vec![UPSTREAM_PORT, FLOW_CLASSIFIER_REJECTED_PORT]
    } else {
        vec![UPSTREAM_PORT]
    }
}

fn interception_selector(case: OutboundProxyE2eCase, remote_ports: &[u16]) -> Selector {
    match case.scenario {
        OutboundProxyScenario::FlowClassified => flow_classified_selector(),
        _ => Selector::term(
            process_selector(case.scenario),
            outbound_traffic_selector(remote_ports.to_vec()),
        ),
    }
}

fn flow_classified_selector() -> Selector {
    Selector::Any {
        selectors: vec![
            Selector::term(
                process_name_selector("xtask"),
                outbound_traffic_selector(vec![UPSTREAM_PORT]),
            ),
            Selector::term(
                process_name_selector("not-xtask"),
                outbound_traffic_selector(vec![FLOW_CLASSIFIER_REJECTED_PORT]),
            ),
        ],
    }
}

fn outbound_traffic_selector(remote_ports: Vec<u16>) -> TrafficSelector {
    TrafficSelector {
        remote_ports,
        directions: vec![Direction::Outbound],
        remote_addresses: vec![LOOPBACK_ADDR.to_string()],
        ..TrafficSelector::default()
    }
}

fn process_name_selector(name: &str) -> ProcessSelector {
    ProcessSelector {
        names: vec![name.to_string()],
        ..ProcessSelector::default()
    }
}

pub(super) fn redirected_remote_ports(
    case: OutboundProxyE2eCase,
    webhook_port: u16,
    policy_source: &PolicySourceFixture<'_>,
) -> Vec<u16> {
    match case.scenario {
        OutboundProxyScenario::OwnerScoped => vec![UPSTREAM_PORT],
        OutboundProxyScenario::FlowClassified => vec![UPSTREAM_PORT, FLOW_CLASSIFIER_REJECTED_PORT],
        OutboundProxyScenario::Standard => {
            let mut ports = vec![UPSTREAM_PORT, webhook_port];
            if let PolicySourceFixture::RemoteBundle { listen_port, .. } = policy_source {
                ports.push(*listen_port);
            }
            ports
        }
    }
}

fn process_selector(scenario: OutboundProxyScenario) -> ProcessSelector {
    match scenario {
        OutboundProxyScenario::OwnerScoped => ProcessSelector {
            uids: vec![super::OWNER_SCOPED_CLIENT_UID],
            gids: vec![super::OWNER_SCOPED_CLIENT_GID],
            ..ProcessSelector::default()
        },
        OutboundProxyScenario::Standard | OutboundProxyScenario::FlowClassified => {
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
