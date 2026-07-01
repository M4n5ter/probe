use std::{
    net::TcpListener,
    path::Path,
    process::ExitCode,
    thread,
    time::{Duration, Instant},
};

use probe_core::{Direction, Selector, TrafficSelector};

use super::support::{
    CLIENT_ADDR, HOST_ADDR, IsolatedClientNamespace, PROCESS_SCOPED_LISTENER_NAME,
    REJECTED_UPSTREAM_ACCEPT_TIMEOUT, TransparentTproxyCase, UPSTREAM_SCENARIOS, UpstreamReport,
    UpstreamScenario, UpstreamServer, assert_client_received_server_response,
    assert_transparent_interception_cleanup, assert_upstream_observed_relayed_request,
    collect_result, process_name_selector, record_result, run_client_output,
    run_transparent_tproxy_case, write_agent_config,
};
use crate::e2e::{
    harness::{ChildSupervisor, UnixSocketReadySignal, e2e_error, stop_running_child},
    loopback::{spawn_agent, wait_for_agent_ready},
};

const CASE: TransparentTproxyCase = TransparentTproxyCase {
    case_name: "e2e-transparent-tproxy-flow-classifier-loopback",
    agent_id: "e2e-transparent-tproxy-flow-classifier-agent",
    config_version: "e2e-transparent-tproxy-flow-classifier-loopback",
    temp_root: "tproxy-flow-classifier",
    label: "e2e transparent TPROXY flow-classified loopback",
};
const MISMATCHING_LISTENER_NAME: &str = "not-xtask";

pub(super) fn run() -> ExitCode {
    run_transparent_tproxy_case(CASE, run_at)
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let config_path = root.join("agent.toml");
    let enforcement_manifest_path = root.join("enforcement.toml");
    let spool_path = root.join("spool");
    let ready_socket_path = root.join("agent.ready.sock");

    write_agent_config(
        &config_path,
        &spool_path,
        &enforcement_manifest_path,
        CASE,
        flow_classified_selector(),
    )?;
    let supervisor = ChildSupervisor::new()?;
    let mut client_namespace = IsolatedClientNamespace::start(&supervisor, CASE)?;
    let client_pid = client_namespace.pid();
    let allowed_scenario = UPSTREAM_SCENARIOS[0];
    let rejected_scenario = UPSTREAM_SCENARIOS[1];
    let allowed_upstream = UpstreamServer::spawn(allowed_scenario)?;
    let rejected_upstream = NoAcceptServer::bind(rejected_scenario.port)?;
    let mut ready_signal = UnixSocketReadySignal::bind(ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;

    let allowed_client_response = run_client_output(client_pid, &allowed_scenario)
        .and_then(|output| client_response_from_successful_output(output, &allowed_scenario));
    let rejected_client_response =
        assert_rejected_client_observation(client_pid, &rejected_scenario);
    let allowed_upstream_report = allowed_upstream.join();
    let rejected_upstream_result = rejected_upstream.assert_no_accept();
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let client_namespace_result = client_namespace.stop();
    let cleanup_result = assert_transparent_interception_cleanup();

    merge_run_results(FlowClassifiedRunResults {
        allowed_scenario,
        rejected_scenario,
        allowed_client_response,
        rejected_client_response,
        allowed_upstream_report,
        rejected_upstream_result,
        agent_result,
        client_namespace_result,
        cleanup_result,
    })
}

fn flow_classified_selector() -> Selector {
    Selector::Any {
        selectors: vec![
            Selector::term(
                process_name_selector(PROCESS_SCOPED_LISTENER_NAME),
                TrafficSelector {
                    local_ports: vec![UPSTREAM_SCENARIOS[0].port],
                    directions: vec![Direction::Inbound],
                    remote_addresses: vec![CLIENT_ADDR.to_string()],
                    ..TrafficSelector::default()
                },
            ),
            Selector::term(
                process_name_selector(MISMATCHING_LISTENER_NAME),
                TrafficSelector {
                    local_ports: vec![UPSTREAM_SCENARIOS[1].port],
                    directions: vec![Direction::Inbound],
                    remote_addresses: vec![CLIENT_ADDR.to_string()],
                    ..TrafficSelector::default()
                },
            ),
        ],
    }
}

fn client_response_from_successful_output(
    output: std::process::Output,
    scenario: &UpstreamScenario,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(e2e_error(format!(
            "allowed client nc failed with {} on port {}: {}",
            output.status,
            scenario.port,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }
}

fn assert_rejected_client_observation(
    client_pid: u32,
    scenario: &UpstreamScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = run_client_output(client_pid, scenario)?;
    if output.stdout.is_empty() {
        return Ok(());
    }
    if output.stdout == scenario.server_response {
        return Err(e2e_error(format!(
            "flow-classified rejected branch unexpectedly received upstream response for port {}",
            scenario.port
        ))
        .into());
    }
    Err(e2e_error(format!(
        "flow-classified rejected branch received unexpected stdout for port {}: {:?}",
        scenario.port,
        String::from_utf8_lossy(&output.stdout)
    ))
    .into())
}

struct NoAcceptServer {
    listener: TcpListener,
}

impl NoAcceptServer {
    fn bind(port: u16) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((HOST_ADDR, port))?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener })
    }

    fn assert_no_accept(self) -> Result<(), Box<dyn std::error::Error>> {
        let deadline = Instant::now() + REJECTED_UPSTREAM_ACCEPT_TIMEOUT;
        loop {
            match self.listener.accept() {
                Ok((stream, peer_addr)) => {
                    drop(stream);
                    return Err(e2e_error(format!(
                        "flow-classified rejected branch unexpectedly reached upstream from {peer_addr}"
                    ))
                    .into());
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
            if Instant::now() >= deadline {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
}

struct FlowClassifiedRunResults {
    allowed_scenario: UpstreamScenario,
    rejected_scenario: UpstreamScenario,
    allowed_client_response: Result<Vec<u8>, Box<dyn std::error::Error>>,
    rejected_client_response: Result<(), Box<dyn std::error::Error>>,
    allowed_upstream_report: Result<UpstreamReport, Box<dyn std::error::Error>>,
    rejected_upstream_result: Result<(), Box<dyn std::error::Error>>,
    agent_result: Result<(), Box<dyn std::error::Error>>,
    client_namespace_result: Result<(), Box<dyn std::error::Error>>,
    cleanup_result: Result<(), Box<dyn std::error::Error>>,
}

fn merge_run_results(results: FlowClassifiedRunResults) -> Result<(), Box<dyn std::error::Error>> {
    let mut errors = Vec::new();
    let FlowClassifiedRunResults {
        allowed_scenario,
        rejected_scenario,
        allowed_client_response,
        rejected_client_response,
        allowed_upstream_report,
        rejected_upstream_result,
        agent_result,
        client_namespace_result,
        cleanup_result,
    } = results;

    if let Some(response) = collect_result(
        format!("allowed client for port {}", allowed_scenario.port),
        allowed_client_response,
        &mut errors,
    ) {
        record_result(
            format!(
                "allowed client response assertion for port {}",
                allowed_scenario.port
            ),
            assert_client_received_server_response(&response, &allowed_scenario),
            &mut errors,
        );
    }
    if let Some(report) = collect_result(
        format!("allowed upstream server for port {}", allowed_scenario.port),
        allowed_upstream_report,
        &mut errors,
    ) {
        record_result(
            format!(
                "allowed upstream server assertion for port {}",
                allowed_scenario.port
            ),
            assert_upstream_observed_relayed_request(&report, &allowed_scenario),
            &mut errors,
        );
    }
    record_result(
        format!(
            "rejected client observed fail-closed close for port {}",
            rejected_scenario.port
        ),
        rejected_client_response,
        &mut errors,
    );
    record_result(
        format!(
            "rejected upstream server for port {} was not reached",
            rejected_scenario.port
        ),
        rejected_upstream_result,
        &mut errors,
    );
    record_result("agent shutdown", agent_result, &mut errors);
    record_result(
        "client namespace shutdown",
        client_namespace_result,
        &mut errors,
    );
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
