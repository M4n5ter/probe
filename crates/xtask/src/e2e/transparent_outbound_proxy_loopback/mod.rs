mod assertions;
mod commands;
mod config;
mod fixtures;

use std::{env, fs, net::Ipv4Addr, path::Path, process::ExitCode, time::Duration};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, e2e_error, ensure_e2e_packages_built,
        reexec_current_case_in_fresh_network_namespace, run_with_temp_root, stop_running_child,
        verify_fresh_network_namespace,
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
use config::{write_agent_config, write_policy_bundle};
use fixtures::{ProxyFixture, ProxyFixtureReport, UpstreamReport, UpstreamServer, run_client};

const IN_NETNS_ENV: &str = "SSSA_PROBE_E2E_TRANSPARENT_OUTBOUND_PROXY_NETNS";
const LOOPBACK_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;
const UPSTREAM_PORT: u16 = 18082;
const PROXY_PORT: u16 = 15001;
const OUTBOUND_BYPASS_MARK: u32 = 0x5353_4102;
const TPROXY_MARK: &str = "0x53534101";
const TPROXY_ROUTE_TABLE: &str = "53534";
const CLIENT_PAYLOAD: &[u8] =
    b"GET /transparent-outbound-proxy-e2e HTTP/1.1\r\nHost: outbound-proxy.test\r\n\r\n";
const SERVER_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\noutbound-proxy\n";
const SERVER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn run() -> ExitCode {
    run_mode(OutboundProxyE2eMode::ManagedRelay)
}

pub(crate) fn run_external() -> ExitCode {
    run_mode(OutboundProxyE2eMode::ExternalProxy)
}

fn run_mode(mode: OutboundProxyE2eMode) -> ExitCode {
    match run_outer(mode) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{} failed: {error}", mode.label());
            ExitCode::FAILURE
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutboundProxyE2eMode {
    ManagedRelay,
    ExternalProxy,
}

impl OutboundProxyE2eMode {
    fn case_name(self) -> &'static str {
        match self {
            Self::ManagedRelay => "e2e-transparent-outbound-proxy-loopback",
            Self::ExternalProxy => "e2e-transparent-outbound-external-proxy-loopback",
        }
    }

    fn temp_root(self) -> &'static str {
        match self {
            Self::ManagedRelay => "transparent-outbound-proxy-loopback",
            Self::ExternalProxy => "out-ext",
        }
    }

    fn agent_id(self) -> &'static str {
        match self {
            Self::ManagedRelay => "e2e-transparent-outbound-proxy-agent",
            Self::ExternalProxy => "e2e-transparent-outbound-external-proxy-agent",
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::ManagedRelay => "e2e transparent outbound managed proxy loopback",
            Self::ExternalProxy => "e2e transparent outbound external proxy loopback",
        }
    }

    fn header_value(self) -> &'static str {
        match self {
            Self::ManagedRelay => "transparent-outbound-proxy",
            Self::ExternalProxy => "transparent-outbound-external-proxy",
        }
    }
}

fn run_outer(mode: OutboundProxyE2eMode) -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(IN_NETNS_ENV).is_some() {
        require_root()?;
        verify_fresh_network_namespace(IN_NETNS_ENV)?;
        run_inner(mode)
    } else {
        ensure_e2e_packages_built(["agent"])?;
        require_root()?;
        reexec_current_case_in_fresh_network_namespace(
            IN_NETNS_ENV,
            mode.case_name(),
            "network-namespace outbound transparent proxy e2e",
        )
    }
}

fn run_inner(mode: OutboundProxyE2eMode) -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root(mode.temp_root(), |root| run_at(root, mode))?;
    println!("{} passed", mode.label());
    Ok(())
}

fn run_at(root: &Path, mode: OutboundProxyE2eMode) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    ip(["link", "set", "lo", "up"])?;

    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let admin_socket_path = root.join("admin.sock");
    let ready_socket_path = root.join("agent.ready.sock");
    let policy_path = root.join("outbound-proxy-e2e-policy.bundle");

    write_policy_bundle(&policy_path)?;
    let webhook_receiver = WebhookBatchReceiver::spawn()?;
    write_agent_config(
        &config_path,
        &spool_path,
        &admin_socket_path,
        &policy_path,
        webhook_receiver.endpoint(),
        webhook_receiver.listen_port(),
        mode,
    )?;

    let supervisor = ChildSupervisor::new()?;
    let upstream = UpstreamServer::spawn()?;
    let proxy_fixture = ProxyFixture::spawn(mode)?;
    let mut ready_signal = UnixSocketReadySignal::bind(ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    assert_outbound_redirect_table_installed(webhook_receiver.listen_port())?;

    let client_response = run_client();
    let upstream_report = upstream.join();
    let proxy_fixture_report = proxy_fixture.join();
    let webhook_wait = match (&client_response, &upstream_report) {
        (Ok(_), Ok(_)) => webhook_receiver.wait_for_batches(1, WEBHOOK_TIMEOUT),
        _ => Ok(()),
    };
    let proxy_metrics = match (&client_response, &upstream_report, &webhook_wait) {
        (Ok(_), Ok(_), Ok(())) => {
            assert_proxy_relay_metrics(agent.child_mut(), &admin_socket_path, mode)
        }
        _ => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let cleanup_result = assert_transparent_interception_cleanup();
    let webhook_result = match webhook_wait {
        Ok(()) => webhook_receiver
            .join()
            .and_then(|batches| assert_webhook_batches(&batches, mode)),
        Err(error) => Err(error),
    };

    merge_run_results(RunResults {
        client_response,
        upstream_report,
        proxy_fixture_report,
        webhook_result,
        proxy_metrics,
        agent_result,
        cleanup_result,
    })
}

struct RunResults {
    client_response: Result<Vec<u8>, Box<dyn std::error::Error>>,
    upstream_report: Result<UpstreamReport, Box<dyn std::error::Error>>,
    proxy_fixture_report: Result<ProxyFixtureReport, Box<dyn std::error::Error>>,
    webhook_result: Result<(), Box<dyn std::error::Error>>,
    proxy_metrics: Result<(), Box<dyn std::error::Error>>,
    agent_result: Result<(), Box<dyn std::error::Error>>,
    cleanup_result: Result<(), Box<dyn std::error::Error>>,
}

fn merge_run_results(results: RunResults) -> Result<(), Box<dyn std::error::Error>> {
    let RunResults {
        client_response,
        upstream_report,
        proxy_fixture_report,
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
