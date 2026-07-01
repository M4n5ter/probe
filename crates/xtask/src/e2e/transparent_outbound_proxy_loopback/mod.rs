mod assertions;
mod commands;
mod config;
mod fixtures;
mod flow_classified;

use std::{env, fs, net::Ipv4Addr, path::Path, process::ExitCode, time::Duration};

use super::{
    agent_admin::send_admin_request,
    harness::{
        ChildSupervisor, HttpSourceServer, UnixSocketReadySignal, e2e_error,
        ensure_e2e_packages_built, reexec_current_case_in_fresh_network_namespace,
        run_with_temp_root, stop_running_child, verify_fresh_network_namespace,
    },
    loopback::{spawn_agent, wait_for_agent_ready},
    webhook_receiver::WebhookBatchReceiver,
};
use assertions::{
    assert_client_received_server_response, assert_outbound_redirect_table_installed,
    assert_proxy_fixture_report, assert_proxy_relay_metrics,
    assert_transparent_interception_cleanup, assert_upstream_observed_request,
    assert_webhook_batches,
};
use commands::{ip, require_root};
use config::{
    AgentConfigInputs, PolicySourceFixture, redirected_remote_ports, remote_policy_bundle_document,
    write_agent_config, write_policy_bundle,
};
use fixtures::{
    ProxyFixture, ProxyFixtureReport, UpstreamReport, UpstreamServer, run_client,
    run_current_process_client,
};

const IN_NETNS_ENV: &str = "TRAFFIC_PROBE_E2E_TRANSPARENT_OUTBOUND_PROXY_NETNS";
const LOOPBACK_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;
const UPSTREAM_PORT: u16 = 18082;
const FLOW_CLASSIFIER_REJECTED_PORT: u16 = 18083;
const PROXY_PORT: u16 = 15001;
const OUTBOUND_BYPASS_MARK: u32 = 0x5450_0102;
const TPROXY_MARK: &str = "0x54500101";
const TPROXY_ROUTE_TABLE: &str = "45100";
const CLIENT_PAYLOAD: &[u8] =
    b"GET /transparent-outbound-proxy-e2e HTTP/1.1\r\nHost: outbound-proxy.test\r\n\r\n";
const SERVER_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\noutbound-proxy\n";
const OWNER_SCOPED_CLIENT_UID: u32 = 65_534;
const OWNER_SCOPED_CLIENT_GID: u32 = 65_534;
const SERVER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
const REMOTE_POLICY_BUNDLE_TARGET: &str = "/policies/outbound-proxy-e2e-policy";
const REMOTE_POLICY_BUNDLE_REQUESTS: usize = 2;

pub(crate) fn run() -> ExitCode {
    run_case(OutboundProxyE2eCase::MANAGED_RELAY)
}

pub(crate) fn run_external() -> ExitCode {
    run_case(OutboundProxyE2eCase::EXTERNAL_PROXY)
}

pub(crate) fn run_owner_scoped() -> ExitCode {
    run_case(OutboundProxyE2eCase::OWNER_SCOPED_MANAGED_RELAY)
}

pub(crate) fn run_remote_policy_bundle() -> ExitCode {
    run_case(OutboundProxyE2eCase::REMOTE_POLICY_BUNDLE)
}

pub(crate) fn run_flow_classified() -> ExitCode {
    run_case(OutboundProxyE2eCase::FLOW_CLASSIFIED)
}

fn run_case(case: OutboundProxyE2eCase) -> ExitCode {
    match run_outer(case) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{} failed: {error}", case.label);
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundProxyMode {
    ManagedRelay,
    ExternalProxy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundProxyScenario {
    Standard,
    OwnerScoped,
    FlowClassified,
}

#[derive(Clone, Copy, Debug)]
struct ClientOwner {
    uid: u32,
    gid: u32,
}

impl OutboundProxyScenario {
    fn client_owner(self) -> Option<ClientOwner> {
        match self {
            Self::OwnerScoped => Some(ClientOwner {
                uid: OWNER_SCOPED_CLIENT_UID,
                gid: OWNER_SCOPED_CLIENT_GID,
            }),
            Self::Standard | Self::FlowClassified => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PolicySourceKind {
    LocalDirectory,
    RemoteBundle,
}

#[derive(Clone, Copy, Debug)]
struct OutboundProxyE2eCase {
    case_name: &'static str,
    temp_root: &'static str,
    agent_id: &'static str,
    label: &'static str,
    header_value: &'static str,
    proxy_mode: OutboundProxyMode,
    scenario: OutboundProxyScenario,
    policy_source: PolicySourceKind,
}

impl OutboundProxyE2eCase {
    const MANAGED_RELAY: Self = Self {
        case_name: "e2e-transparent-outbound-proxy-loopback",
        temp_root: "transparent-outbound-proxy-loopback",
        agent_id: "e2e-transparent-outbound-proxy-agent",
        label: "e2e transparent outbound managed proxy loopback",
        header_value: "transparent-outbound-proxy",
        proxy_mode: OutboundProxyMode::ManagedRelay,
        scenario: OutboundProxyScenario::Standard,
        policy_source: PolicySourceKind::LocalDirectory,
    };

    const EXTERNAL_PROXY: Self = Self {
        case_name: "e2e-transparent-outbound-external-proxy-loopback",
        temp_root: "out-ext",
        agent_id: "e2e-transparent-outbound-external-proxy-agent",
        label: "e2e transparent outbound external proxy loopback",
        header_value: "transparent-outbound-external-proxy",
        proxy_mode: OutboundProxyMode::ExternalProxy,
        scenario: OutboundProxyScenario::Standard,
        policy_source: PolicySourceKind::LocalDirectory,
    };

    const OWNER_SCOPED_MANAGED_RELAY: Self = Self {
        case_name: "e2e-transparent-outbound-owner-proxy-loopback",
        temp_root: "out-owner",
        agent_id: "e2e-transparent-outbound-owner-proxy-agent",
        label: "e2e transparent outbound owner-scoped proxy loopback",
        header_value: "transparent-outbound-owner-proxy",
        proxy_mode: OutboundProxyMode::ManagedRelay,
        scenario: OutboundProxyScenario::OwnerScoped,
        policy_source: PolicySourceKind::LocalDirectory,
    };

    const REMOTE_POLICY_BUNDLE: Self = Self {
        case_name: "e2e-transparent-outbound-remote-policy-bundle-loopback",
        temp_root: "out-remote-policy",
        agent_id: "e2e-transparent-outbound-remote-policy-agent",
        label: "e2e transparent outbound remote policy bundle loopback",
        header_value: "transparent-outbound-remote-policy",
        proxy_mode: OutboundProxyMode::ManagedRelay,
        scenario: OutboundProxyScenario::Standard,
        policy_source: PolicySourceKind::RemoteBundle,
    };

    const FLOW_CLASSIFIED: Self = Self {
        case_name: "e2e-transparent-outbound-flow-classifier-loopback",
        temp_root: "out-flow-classifier",
        agent_id: "e2e-transparent-outbound-flow-classifier-agent",
        label: "e2e transparent outbound flow-classified proxy loopback",
        header_value: "transparent-outbound-flow-classifier",
        proxy_mode: OutboundProxyMode::ManagedRelay,
        scenario: OutboundProxyScenario::FlowClassified,
        policy_source: PolicySourceKind::LocalDirectory,
    };

    fn reload_policy_after_activation(self) -> bool {
        self.policy_source == PolicySourceKind::RemoteBundle
    }

    fn client_owner(self) -> Option<ClientOwner> {
        self.scenario.client_owner()
    }

    fn is_flow_classified(self) -> bool {
        self.scenario == OutboundProxyScenario::FlowClassified
    }
}

fn run_outer(case: OutboundProxyE2eCase) -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(IN_NETNS_ENV).is_some() {
        require_root()?;
        verify_fresh_network_namespace(IN_NETNS_ENV)?;
        run_inner(case)
    } else {
        ensure_e2e_packages_built(["agent"])?;
        require_root()?;
        reexec_current_case_in_fresh_network_namespace(
            IN_NETNS_ENV,
            case.case_name,
            "network-namespace outbound transparent proxy e2e",
        )
    }
}

fn run_inner(case: OutboundProxyE2eCase) -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root(case.temp_root, |root| run_at(root, case))?;
    println!("{} passed", case.label);
    Ok(())
}

fn run_at(root: &Path, case: OutboundProxyE2eCase) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    ip(["link", "set", "lo", "up"])?;

    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let admin_socket_path = root.join("admin.sock");
    let ready_socket_path = root.join("agent.ready.sock");
    let policy_path = root.join("outbound-proxy-e2e-policy.bundle");
    let enforcement_manifest_path = root.join("enforcement.toml");

    let (policy_source, remote_policy_source) = prepare_policy_source(case, &policy_path)?;
    let webhook_receiver = WebhookBatchReceiver::spawn()?;
    let redirect_ports =
        redirected_remote_ports(case, webhook_receiver.listen_port(), &policy_source);
    write_agent_config(AgentConfigInputs {
        path: &config_path,
        spool_path: &spool_path,
        admin_socket_path: &admin_socket_path,
        enforcement_manifest_path: &enforcement_manifest_path,
        policy_source,
        webhook_endpoint: webhook_receiver.endpoint(),
        redirect_ports: &redirect_ports,
        case,
    })?;

    let supervisor = ChildSupervisor::new()?;
    let upstream = UpstreamServer::spawn()?;
    let rejected_upstream = flow_classified::RejectedUpstreamProbe::bind_for_case(case)?;
    let proxy_fixture = ProxyFixture::spawn(case.proxy_mode)?;
    let mut ready_signal = UnixSocketReadySignal::bind(ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    assert_outbound_redirect_table_installed(&redirect_ports, case)?;
    let remote_policy_reload = reload_remote_policy_if_configured(
        case.reload_policy_after_activation(),
        &admin_socket_path,
    );

    let client_response = run_primary_client(case);
    let rejected_client_observation = flow_classified::assert_rejected_client_for_case(case);
    let upstream_report = upstream.join();
    let rejected_upstream_result =
        flow_classified::assert_rejected_upstream_for_case(rejected_upstream);
    let unmatched_owner_bypass = match (&client_response, &upstream_report, case.scenario) {
        (Ok(_), Ok(_), OutboundProxyScenario::OwnerScoped) => {
            assert_unmatched_owner_reaches_upstream_directly()
        }
        _ => Ok(()),
    };
    let proxy_fixture_report = proxy_fixture.join();
    let webhook_wait = match (&client_response, &upstream_report) {
        (Ok(_), Ok(_)) => webhook_receiver.wait_for_batches(1, WEBHOOK_TIMEOUT),
        _ => Ok(()),
    };
    let proxy_metrics = match (&client_response, &upstream_report, &webhook_wait) {
        (Ok(_), Ok(_), Ok(())) => {
            assert_proxy_relay_metrics(agent.child_mut(), &admin_socket_path, case)
        }
        _ => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let cleanup_result = assert_transparent_interception_cleanup();
    let remote_policy_source_result = assert_remote_policy_source_requests(remote_policy_source);
    let webhook_result = match webhook_wait {
        Ok(()) => webhook_receiver
            .join()
            .and_then(|batches| assert_webhook_batches(&batches, case)),
        Err(error) => Err(error),
    };

    merge_run_results(RunResults {
        client_response,
        rejected_client_observation,
        upstream_report,
        rejected_upstream_result,
        unmatched_owner_bypass,
        proxy_fixture_report,
        remote_policy_reload,
        remote_policy_source_result,
        webhook_result,
        proxy_metrics,
        agent_result,
        cleanup_result,
    })
}

fn run_primary_client(case: OutboundProxyE2eCase) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if case.is_flow_classified() {
        run_current_process_client(UPSTREAM_PORT)
    } else {
        run_client(case.client_owner())
    }
}

fn prepare_policy_source<'a>(
    case: OutboundProxyE2eCase,
    policy_path: &'a Path,
) -> Result<(PolicySourceFixture<'a>, Option<HttpSourceServer>), Box<dyn std::error::Error>> {
    match case.policy_source {
        PolicySourceKind::LocalDirectory => {
            write_policy_bundle(policy_path)?;
            Ok((PolicySourceFixture::LocalDirectory(policy_path), None))
        }
        PolicySourceKind::RemoteBundle => {
            let source = HttpSourceServer::spawn(
                REMOTE_POLICY_BUNDLE_TARGET,
                "application/toml",
                remote_policy_bundle_document(),
            )?;
            let fixture = PolicySourceFixture::RemoteBundle {
                endpoint: source.endpoint(),
                listen_port: source.listen_port(),
            };
            Ok((fixture, Some(source)))
        }
    }
}

struct RunResults {
    client_response: Result<Vec<u8>, Box<dyn std::error::Error>>,
    rejected_client_observation: Result<(), Box<dyn std::error::Error>>,
    upstream_report: Result<UpstreamReport, Box<dyn std::error::Error>>,
    rejected_upstream_result: Result<(), Box<dyn std::error::Error>>,
    unmatched_owner_bypass: Result<(), Box<dyn std::error::Error>>,
    proxy_fixture_report: Result<ProxyFixtureReport, Box<dyn std::error::Error>>,
    remote_policy_reload: Result<(), Box<dyn std::error::Error>>,
    remote_policy_source_result: Result<(), Box<dyn std::error::Error>>,
    webhook_result: Result<(), Box<dyn std::error::Error>>,
    proxy_metrics: Result<(), Box<dyn std::error::Error>>,
    agent_result: Result<(), Box<dyn std::error::Error>>,
    cleanup_result: Result<(), Box<dyn std::error::Error>>,
}

fn merge_run_results(results: RunResults) -> Result<(), Box<dyn std::error::Error>> {
    let RunResults {
        client_response,
        rejected_client_observation,
        upstream_report,
        rejected_upstream_result,
        unmatched_owner_bypass,
        proxy_fixture_report,
        remote_policy_reload,
        remote_policy_source_result,
        webhook_result,
        proxy_metrics,
        agent_result,
        cleanup_result,
    } = results;

    let mut errors = Vec::new();
    match client_response {
        Ok(response) => record_result(
            "client response assertion",
            assert_client_received_server_response(&response),
            &mut errors,
        ),
        Err(error) => errors.push(format!("client failed: {error}")),
    }
    match upstream_report {
        Ok(report) => record_result(
            "upstream request assertion",
            assert_upstream_observed_request(&report),
            &mut errors,
        ),
        Err(error) => errors.push(format!("upstream server failed: {error}")),
    }
    record_result(
        "flow-classified rejected client observation",
        rejected_client_observation,
        &mut errors,
    );
    record_result(
        "flow-classified rejected upstream isolation",
        rejected_upstream_result,
        &mut errors,
    );
    record_result(
        "unmatched owner bypass",
        unmatched_owner_bypass,
        &mut errors,
    );
    record_result("remote policy reload", remote_policy_reload, &mut errors);
    record_result(
        "remote policy source requests",
        remote_policy_source_result,
        &mut errors,
    );
    match proxy_fixture_report {
        Ok(report) => record_result(
            "proxy fixture assertion",
            assert_proxy_fixture_report(report),
            &mut errors,
        ),
        Err(error) => errors.push(format!("proxy fixture failed: {error}")),
    }
    record_result("webhook exporter", webhook_result, &mut errors);
    record_result("transparent proxy metrics", proxy_metrics, &mut errors);
    record_result("agent shutdown", agent_result, &mut errors);
    record_result(
        "transparent interception cleanup",
        cleanup_result,
        &mut errors,
    );
    if errors.is_empty() {
        Ok(())
    } else {
        Err(e2e_error(errors.join("; ")).into())
    }
}

fn reload_remote_policy_if_configured(
    enabled: bool,
    admin_socket_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if !enabled {
        return Ok(());
    }
    let response = send_admin_request(
        admin_socket_path,
        serde_json::json!({ "command": "reload_policies" }),
    )?;
    if response["kind"] == serde_json::json!("policy_reload")
        && response["loaded_count"] == serde_json::json!(1)
    {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "unexpected remote policy reload response: {response}"
        ))
        .into())
    }
}

fn assert_remote_policy_source_requests(
    remote_policy_source: Option<HttpSourceServer>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(source) = remote_policy_source else {
        return Ok(());
    };
    let requests = source.finish()?;
    if requests == REMOTE_POLICY_BUNDLE_REQUESTS {
        return Ok(());
    }
    Err(e2e_error(format!(
        "expected {REMOTE_POLICY_BUNDLE_REQUESTS} remote policy bundle GETs, got {requests}"
    ))
    .into())
}

fn assert_unmatched_owner_reaches_upstream_directly() -> Result<(), Box<dyn std::error::Error>> {
    let upstream = UpstreamServer::spawn()?;
    let response = run_client(None);
    let report = upstream.join();
    assert_client_received_server_response(&response?)?;
    assert_upstream_observed_request(&report?)?;
    Ok(())
}

fn record_result(
    label: impl Into<String>,
    result: Result<(), Box<dyn std::error::Error>>,
    errors: &mut Vec<String>,
) {
    let label = label.into();
    if let Err(error) = result {
        errors.push(format!("{label} failed: {error}"));
    }
}
