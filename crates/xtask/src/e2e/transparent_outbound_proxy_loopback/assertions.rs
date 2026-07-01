use std::{
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

use exporter::CompressionCodec;
use probe_core::{EventEnvelope, EventKind};

use super::super::{
    harness::e2e_error, loopback::send_admin_request, webhook_receiver::ReceivedBatch,
};
use super::commands::{ip_output, ip_route_table_output, nft_command, nft_output};
use super::fixtures::{ExternalProxyReport, ProxyFixtureReport, UpstreamReport};
use super::{
    CLIENT_PAYLOAD, LOOPBACK_ADDR, OUTBOUND_BYPASS_MARK, OutboundProxyE2eCase, OutboundProxyMode,
    OutboundProxyScenario, PROXY_PORT, SERVER_RESPONSE, TPROXY_MARK, TPROXY_ROUTE_TABLE,
};

const METRICS_TIMEOUT: Duration = Duration::from_secs(10);
const METRICS_POLL_INTERVAL: Duration = Duration::from_millis(100);

pub(super) fn assert_proxy_relay_metrics(
    agent: &mut Child,
    admin_socket_path: &Path,
    case: OutboundProxyE2eCase,
) -> Result<(), Box<dyn std::error::Error>> {
    match case.proxy_mode {
        OutboundProxyMode::ManagedRelay => {
            wait_for_proxy_relay_metrics(agent, admin_socket_path, expected_relay_metrics(case))
        }
        OutboundProxyMode::ExternalProxy => {
            let metrics = read_proxy_relay_metrics(admin_socket_path)?;
            let expected = expected_relay_metrics(case);
            if metrics.matches_expected(expected) {
                Ok(())
            } else {
                Err(e2e_error(format!(
                    "external outbound proxy should not use agent-managed relay metrics {expected:?}; got {metrics:?}"
                ))
                .into())
            }
        }
    }
}

fn expected_relay_metrics(case: OutboundProxyE2eCase) -> ExpectedProxyRelayMetrics {
    match (case.proxy_mode, case.scenario) {
        (OutboundProxyMode::ManagedRelay, OutboundProxyScenario::FlowClassified) => {
            ExpectedProxyRelayMetrics {
                accepted_relays: 1,
                rejected_relays: 1,
                relay_failures: 0,
                upstream_connect_successes: 1,
                upstream_connect_failures: 0,
            }
        }
        (OutboundProxyMode::ManagedRelay, _) => ExpectedProxyRelayMetrics {
            accepted_relays: 1,
            rejected_relays: 0,
            relay_failures: 0,
            upstream_connect_successes: 1,
            upstream_connect_failures: 0,
        },
        (OutboundProxyMode::ExternalProxy, _) => ExpectedProxyRelayMetrics {
            accepted_relays: 0,
            rejected_relays: 0,
            relay_failures: 0,
            upstream_connect_successes: 0,
            upstream_connect_failures: 0,
        },
    }
}

fn wait_for_proxy_relay_metrics(
    agent: &mut Child,
    admin_socket_path: &Path,
    expected: ExpectedProxyRelayMetrics,
) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + METRICS_TIMEOUT;
    loop {
        match read_proxy_relay_metrics(admin_socket_path) {
            Ok(metrics) if metrics.matches_expected(expected) => return Ok(()),
            Ok(metrics) if metrics.has_unexpected_failure(expected) => {
                return Err(e2e_error(format!(
                    "transparent proxy reported relay failure metrics: {metrics:?}"
                ))
                .into());
            }
            Ok(_) => {}
            Err(error) => {
                if let Some(status) = agent.try_wait()? {
                    return Err(e2e_error(format!(
                        "agent exited with {status} before transparent proxy metrics were available: {error}"
                    ))
                    .into());
                }
            }
        }
        if Instant::now() >= deadline {
            let metrics = read_proxy_relay_metrics(admin_socket_path)
                .map(|metrics| format!("{metrics:?}"))
                .unwrap_or_else(|error| format!("unavailable: {error}"));
            return Err(e2e_error(format!(
                "timed out waiting for transparent proxy relay metrics {expected:?}; last metrics {metrics}"
            ))
            .into());
        }
        thread::sleep(METRICS_POLL_INTERVAL);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExpectedProxyRelayMetrics {
    accepted_relays: u64,
    rejected_relays: u64,
    relay_failures: u64,
    upstream_connect_successes: u64,
    upstream_connect_failures: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProxyRelayMetrics {
    accepted_relays: u64,
    rejected_relays: u64,
    relay_failures: u64,
    listener_failures: u64,
    upstream_connect_successes: u64,
    upstream_connect_failures: u64,
}

impl ProxyRelayMetrics {
    fn matches_expected(self, expected: ExpectedProxyRelayMetrics) -> bool {
        self.accepted_relays == expected.accepted_relays
            && self.rejected_relays == expected.rejected_relays
            && self.relay_failures == expected.relay_failures
            && self.upstream_connect_successes == expected.upstream_connect_successes
            && self.upstream_connect_failures == expected.upstream_connect_failures
            && self.listener_failures == 0
    }

    fn has_unexpected_failure(self, expected: ExpectedProxyRelayMetrics) -> bool {
        self.accepted_relays > expected.accepted_relays
            || self.rejected_relays > expected.rejected_relays
            || self.relay_failures > expected.relay_failures
            || self.upstream_connect_successes > expected.upstream_connect_successes
            || self.listener_failures > 0
            || self.upstream_connect_failures > expected.upstream_connect_failures
    }
}

fn read_proxy_relay_metrics(
    admin_socket_path: &Path,
) -> Result<ProxyRelayMetrics, Box<dyn std::error::Error>> {
    let response = send_admin_request(
        admin_socket_path,
        serde_json::json!({ "command": "metrics" }),
    )?;
    let proxy = &response["metrics"]["transparent_proxy"];
    let upstream = &proxy["upstream_connects"];
    Ok(ProxyRelayMetrics {
        accepted_relays: metric_u64(&response, proxy, "accepted_relays")?,
        rejected_relays: metric_u64(&response, proxy, "rejected_relays")?,
        relay_failures: metric_u64(&response, proxy, "relay_failures")?,
        listener_failures: metric_u64(&response, proxy, "listener_failures")?,
        upstream_connect_successes: metric_u64(&response, upstream, "connect_successes")?,
        upstream_connect_failures: metric_u64(&response, upstream, "connect_failures")?,
    })
}

fn metric_u64(
    response: &serde_json::Value,
    object: &serde_json::Value,
    field: &'static str,
) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(object[field].as_u64().ok_or_else(|| {
        e2e_error(format!(
            "admin metrics response omitted transparent proxy metric {field}: {response}"
        ))
    })?)
}

pub(super) fn assert_outbound_redirect_table_installed(
    remote_ports: &[u16],
    case: OutboundProxyE2eCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let listing = nft_output(["list", "table", "inet", "traffic_probe"])?;
    let mut expected_snippets = vec![
        "chain outbound_transparent_proxy".to_string(),
        "type nat hook output priority dstnat; policy accept;".to_string(),
        format!("meta mark {} return", outbound_bypass_mark_text()),
        format!("ip daddr {LOOPBACK_ADDR}"),
        format!("redirect to :{PROXY_PORT}"),
        expected_tcp_dport_snippet(remote_ports)?,
    ];
    if case.scenario == OutboundProxyScenario::OwnerScoped {
        expected_snippets.push(format!("meta skuid {}", super::OWNER_SCOPED_CLIENT_UID));
        expected_snippets.push(format!("meta skgid {}", super::OWNER_SCOPED_CLIENT_GID));
    }
    for snippet in expected_snippets {
        if !listing.contains(&snippet) {
            return Err(e2e_error(format!(
                "outbound transparent proxy nft table is missing expected snippet `{snippet}`: {listing}"
            ))
            .into());
        }
    }
    Ok(())
}

fn expected_tcp_dport_snippet(remote_ports: &[u16]) -> Result<String, Box<dyn std::error::Error>> {
    let mut ports = remote_ports.to_vec();
    ports.sort_unstable();
    ports.dedup();
    match ports.as_slice() {
        [] => Err(e2e_error("outbound transparent proxy expected no redirect ports").into()),
        [port] => Ok(format!("tcp dport {port}")),
        _ => Ok(format!(
            "tcp dport {{ {} }}",
            ports
                .into_iter()
                .map(|port| port.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        )),
    }
}

fn outbound_bypass_mark_text() -> String {
    format!("0x{OUTBOUND_BYPASS_MARK:08x}")
}

pub(super) fn assert_transparent_interception_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    assert_owned_table_removed()?;
    assert_policy_routing_removed()?;
    Ok(())
}

fn assert_owned_table_removed() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(nft_command()?)
        .args(["list", "table", "inet", "traffic_probe"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if output.status.success() {
        return Err(e2e_error(format!(
            "transparent interception nft table still exists after agent shutdown: {}",
            String::from_utf8_lossy(&output.stdout)
        ))
        .into());
    }
    Ok(())
}

fn assert_policy_routing_removed() -> Result<(), Box<dyn std::error::Error>> {
    for family in ["-4", "-6"] {
        let rules = ip_output([family, "rule", "show"], "ip rule show")?;
        if rules.contains(TPROXY_MARK) {
            return Err(e2e_error(format!(
                "transparent interception policy rule still references {TPROXY_MARK}: {rules:?}"
            ))
            .into());
        }

        let routes = ip_route_table_output(family)?;
        if !routes.trim().is_empty() {
            return Err(e2e_error(format!(
                "transparent interception route table {TPROXY_ROUTE_TABLE} still has routes: {routes:?}"
            ))
            .into());
        }
    }
    Ok(())
}

pub(super) fn assert_upstream_observed_request(
    report: &UpstreamReport,
) -> Result<(), Box<dyn std::error::Error>> {
    if report.peer_addr.ip() != LOOPBACK_ADDR {
        return Err(e2e_error(format!(
            "upstream peer mismatch: expected relay loopback address {LOOPBACK_ADDR}, got {}",
            report.peer_addr
        ))
        .into());
    }
    if !report.request.starts_with(CLIENT_PAYLOAD) {
        return Err(e2e_error(format!(
            "upstream server received unexpected payload: {:?}",
            String::from_utf8_lossy(&report.request)
        ))
        .into());
    }
    Ok(())
}

pub(super) fn assert_proxy_fixture_report(
    report: ProxyFixtureReport,
) -> Result<(), Box<dyn std::error::Error>> {
    match report {
        ProxyFixtureReport::ManagedRelay => Ok(()),
        ProxyFixtureReport::ExternalProxy(report) => {
            assert_external_proxy_observed_redirected_client(&report)
        }
    }
}

fn assert_external_proxy_observed_redirected_client(
    report: &ExternalProxyReport,
) -> Result<(), Box<dyn std::error::Error>> {
    if report.client_peer_addr.ip() != LOOPBACK_ADDR {
        return Err(e2e_error(format!(
            "external proxy peer mismatch: expected redirected client loopback address {LOOPBACK_ADDR}, got {}",
            report.client_peer_addr
        ))
        .into());
    }
    if !report.request.starts_with(CLIENT_PAYLOAD) {
        return Err(e2e_error(format!(
            "external proxy received unexpected payload: {:?}",
            String::from_utf8_lossy(&report.request)
        ))
        .into());
    }
    if report.upstream_response == SERVER_RESPONSE {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "external proxy did not receive upstream response through marked socket: {:?}",
            String::from_utf8_lossy(&report.upstream_response)
        ))
        .into())
    }
}

pub(super) fn assert_client_received_server_response(
    response: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if response == SERVER_RESPONSE {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "client did not receive server response through transparent outbound proxy: {:?}",
            String::from_utf8_lossy(response)
        ))
        .into())
    }
}

pub(super) fn assert_webhook_batches(
    batches: &[ReceivedBatch],
    case: OutboundProxyE2eCase,
) -> Result<(), Box<dyn std::error::Error>> {
    if batches.is_empty() {
        return Err(e2e_error("webhook receiver captured no batches").into());
    }
    if !batches
        .iter()
        .all(|batch| batch.codec == CompressionCodec::None)
    {
        return Err(e2e_error("webhook receiver observed an unexpected codec").into());
    }
    if !batches.iter().all(|batch| {
        batch
            .headers
            .get("x-traffic-probe-e2e")
            .is_some_and(|value| value == case.header_value)
    }) {
        return Err(e2e_error("webhook receiver did not observe configured header").into());
    }

    let exported = batches
        .iter()
        .flat_map(|batch| batch.batch.events.iter())
        .map(|event| serde_json::from_slice::<EventEnvelope>(&event.payload))
        .collect::<Result<Vec<_>, _>>()?;
    let expected = expected_policy_alert_message();
    if exported.iter().any(|event| {
        matches!(
            event.kind(),
            EventKind::PolicyAlert(alert) if alert.message == expected
        )
    }) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "webhook export batches did not contain expected policy alert {expected:?}"
    ))
    .into())
}

fn expected_policy_alert_message() -> String {
    "transparent outbound proxy observed /transparent-outbound-proxy-e2e".to_string()
}
