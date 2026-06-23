use std::{
    collections::BTreeMap,
    env, fs,
    io::{Read, Write},
    net::{Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, e2e_error, ensure_e2e_packages_built,
        reexec_current_case_in_fresh_network_namespace, run_with_temp_root, stop_running_child,
        trusted_system_command, verify_fresh_network_namespace,
    },
    loopback::{send_admin_request, spawn_agent, wait_for_agent_ready},
    webhook_receiver::{ReceivedBatch, WebhookBatchReceiver},
};
use exporter::CompressionCodec;
use probe_config::{
    AgentConfig, CaptureSelection, CompressionCodecName, ExportFailureBackoffConfig,
    ExportWorkerScheduleConfig, ExporterConfig, ExporterTransportConfig, PolicyConfig,
    TransparentInterceptionProxyConfig, TransparentInterceptionProxyModeConfig,
    TransparentInterceptionStrategyConfig,
};
use probe_core::{
    Direction, EnforcementMode, EventEnvelope, EventKind, ProcessSelector, Selector,
    TrafficSelector,
};

const CASE_NAME: &str = "e2e-transparent-outbound-proxy-loopback";
const COLLECTOR_SINK: &str = "collector";
const POLICY_ID: &str = "outbound-proxy-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const IN_NETNS_ENV: &str = "SSSA_PROBE_E2E_TRANSPARENT_OUTBOUND_PROXY_NETNS";
const LOOPBACK_ADDR: Ipv4Addr = Ipv4Addr::LOCALHOST;
const UPSTREAM_PORT: u16 = 18082;
const PROXY_PORT: u16 = 15001;
const OUTBOUND_BYPASS_MARK: &str = "0x53534102";
const TPROXY_MARK: &str = "0x53534101";
const TPROXY_ROUTE_TABLE: &str = "53534";
const CLIENT_PAYLOAD: &[u8] =
    b"GET /transparent-outbound-proxy-e2e HTTP/1.1\r\nHost: outbound-proxy.test\r\n\r\n";
const SERVER_RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 15\r\n\r\noutbound-proxy\n";
const SERVER_ACCEPT_TIMEOUT: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
const METRICS_TIMEOUT: Duration = Duration::from_secs(10);
const METRICS_POLL_INTERVAL: Duration = Duration::from_millis(100);
const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);

pub(crate) fn run() -> ExitCode {
    match run_outer() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e transparent outbound proxy loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_outer() -> Result<(), Box<dyn std::error::Error>> {
    if env::var_os(IN_NETNS_ENV).is_some() {
        require_root()?;
        verify_fresh_network_namespace(IN_NETNS_ENV)?;
        run_inner()
    } else {
        ensure_e2e_packages_built(["agent"])?;
        require_root()?;
        reexec_current_case_in_fresh_network_namespace(
            IN_NETNS_ENV,
            CASE_NAME,
            "network-namespace outbound transparent proxy e2e",
        )
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("transparent-outbound-proxy-loopback", run_at)?;
    println!("e2e transparent outbound proxy loopback passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
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
    )?;
    let supervisor = ChildSupervisor::new()?;
    let upstream = UpstreamServer::spawn()?;
    let mut ready_signal = UnixSocketReadySignal::bind(ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    assert_outbound_redirect_table_installed(webhook_receiver.listen_port())?;

    let client_response = run_client();
    let upstream_report = upstream.join();
    let webhook_wait = match (&client_response, &upstream_report) {
        (Ok(_), Ok(_)) => webhook_receiver.wait_for_batches(1, WEBHOOK_TIMEOUT),
        _ => Ok(()),
    };
    let proxy_metrics = match (&client_response, &upstream_report, &webhook_wait) {
        (Ok(_), Ok(_), Ok(())) => wait_for_proxy_relay_metrics(
            agent.child_mut(),
            &admin_socket_path,
            ExpectedProxyRelayMetrics {
                accepted_relays: 1,
                upstream_connect_successes: 1,
            },
        ),
        _ => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let cleanup_result = assert_transparent_interception_cleanup();
    let webhook_result = match webhook_wait {
        Ok(()) => webhook_receiver
            .join()
            .and_then(|batches| assert_webhook_batches(&batches)),
        Err(error) => Err(error),
    };

    merge_run_results(
        client_response,
        upstream_report,
        webhook_result,
        proxy_metrics,
        agent_result,
        cleanup_result,
    )
}

fn write_agent_config(
    path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    policy_path: &Path,
    webhook_endpoint: String,
    webhook_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-transparent-outbound-proxy-agent".to_string(),
        config_version: CASE_NAME.to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some("lo".to_string());
    config.capture.libpcap.bpf_filter =
        format!("tcp and (port {UPSTREAM_PORT} or port {PROXY_PORT})");
    config.capture.libpcap.read_timeout_ms = 100;
    config.storage.path = spool_path.to_path_buf();
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
            endpoint: webhook_endpoint,
            headers: BTreeMap::from([(
                "x-sssa-e2e".to_string(),
                "transparent-outbound-proxy".to_string(),
            )]),
            tls: Default::default(),
        },
        codec: CompressionCodecName::None,
        worker: Default::default(),
    });
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        path: policy_path.to_path_buf(),
        enabled: true,
        selector: None,
    });
    config.enforcement.mode = EnforcementMode::Enforce;
    config.enforcement.interception.strategy =
        TransparentInterceptionStrategyConfig::OutboundTransparentProxy;
    config.enforcement.interception.proxy = TransparentInterceptionProxyConfig {
        mode: TransparentInterceptionProxyModeConfig::ManagedTcpRelay,
        listen_port: Some(PROXY_PORT),
        ..TransparentInterceptionProxyConfig::default()
    };
    config.enforcement.interception.selector = Some(Selector::term(
        ProcessSelector::default(),
        TrafficSelector {
            remote_ports: vec![UPSTREAM_PORT, webhook_port],
            directions: vec![Direction::Outbound],
            remote_addresses: vec![LOOPBACK_ADDR.to_string()],
            ..TrafficSelector::default()
        },
    ));
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn write_policy_bundle(path: &Path) -> Result<(), std::io::Error> {
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
        r#"
function on_http_request_headers(event)
  local target = event.kind.target or ""
  if target == "/transparent-outbound-proxy-e2e" then
    return probe.emit_alert("transparent outbound proxy observed " .. target)
  end
end
"#,
    )
}

struct UpstreamServer {
    report: mpsc::Receiver<Result<UpstreamReport, String>>,
    thread: thread::JoinHandle<()>,
}

impl UpstreamServer {
    fn spawn() -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((LOOPBACK_ADDR, UPSTREAM_PORT))?;
        listener.set_nonblocking(true)?;
        let (sender, report) = mpsc::channel();
        let thread = thread::spawn(move || {
            let result = run_upstream_server(listener).map_err(|error| error.to_string());
            let _ = sender.send(result);
        });
        Ok(Self { report, thread })
    }

    fn join(self) -> Result<UpstreamReport, Box<dyn std::error::Error>> {
        let result = self
            .report
            .recv_timeout(SERVER_ACCEPT_TIMEOUT + Duration::from_secs(1))
            .map_err(|error| e2e_error(format!("upstream server did not report: {error}")))?;
        self.thread
            .join()
            .map_err(|_| e2e_error("upstream server thread panicked"))?;
        result.map_err(|error| e2e_error(error).into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UpstreamReport {
    peer_addr: SocketAddr,
    request: Vec<u8>,
}

fn run_upstream_server(
    listener: TcpListener,
) -> Result<UpstreamReport, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + SERVER_ACCEPT_TIMEOUT;
    let (mut stream, peer_addr) = loop {
        match listener.accept() {
            Ok(accepted) => break accepted,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
        if Instant::now() >= deadline {
            return Err(e2e_error("upstream server timed out waiting for relayed client").into());
        }
        thread::sleep(Duration::from_millis(20));
    };
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut request = Vec::new();
    let mut buffer = [0_u8; 1024];
    let read = stream.read(&mut buffer)?;
    request.extend_from_slice(&buffer[..read]);
    stream.write_all(SERVER_RESPONSE)?;
    Ok(UpstreamReport { peer_addr, request })
}

fn run_client() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let host = LOOPBACK_ADDR.to_string();
    let port = UPSTREAM_PORT.to_string();
    let mut child = Command::new(nc_command()?)
        .args(["-w", "2", &host, &port])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .ok_or_else(|| e2e_error("failed to open nc stdin"))?
        .write_all(CLIENT_PAYLOAD)?;
    let output = wait_with_timeout(child, CLIENT_TIMEOUT)?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(e2e_error(format!(
            "client nc failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
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
            Ok(metrics) if metrics.has_failure() => {
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
    upstream_connect_successes: u64,
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
            && self.upstream_connect_successes == expected.upstream_connect_successes
            && !self.has_failure()
    }

    fn has_failure(self) -> bool {
        self.rejected_relays > 0
            || self.relay_failures > 0
            || self.listener_failures > 0
            || self.upstream_connect_failures > 0
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

fn assert_outbound_redirect_table_installed(
    webhook_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let listing = nft_output(["list", "table", "inet", "sssa_probe"])?;
    let expected_snippets = [
        "chain outbound_transparent_proxy".to_string(),
        "type nat hook output priority dstnat; policy accept;".to_string(),
        format!("meta mark {OUTBOUND_BYPASS_MARK} return"),
        format!(
            "meta l4proto tcp meta nfproto ipv4 tcp dport {{ {UPSTREAM_PORT}, {webhook_port} }} redirect to :{PROXY_PORT}"
        ),
        format!(
            "meta l4proto tcp meta nfproto ipv6 tcp dport {{ {UPSTREAM_PORT}, {webhook_port} }} redirect to :{PROXY_PORT}"
        ),
    ];
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

fn assert_transparent_interception_cleanup() -> Result<(), Box<dyn std::error::Error>> {
    assert_owned_table_removed()?;
    assert_policy_routing_removed()?;
    Ok(())
}

fn assert_owned_table_removed() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(nft_command()?)
        .args(["list", "table", "inet", "sssa_probe"])
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

fn assert_upstream_observed_request(
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

fn assert_client_received_server_response(
    response: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    if response == SERVER_RESPONSE {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "client did not receive server response through managed relay: {:?}",
            String::from_utf8_lossy(response)
        ))
        .into())
    }
}

fn assert_webhook_batches(batches: &[ReceivedBatch]) -> Result<(), Box<dyn std::error::Error>> {
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
            .get("x-sssa-e2e")
            .is_some_and(|value| value == "transparent-outbound-proxy")
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

fn merge_run_results(
    client_response: Result<Vec<u8>, Box<dyn std::error::Error>>,
    upstream_report: Result<UpstreamReport, Box<dyn std::error::Error>>,
    webhook_result: Result<(), Box<dyn std::error::Error>>,
    proxy_metrics: Result<(), Box<dyn std::error::Error>>,
    agent_result: Result<(), Box<dyn std::error::Error>>,
    cleanup_result: Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
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

fn nft_output<const N: usize>(args: [&str; N]) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(nft_command()?)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    ensure_command_success(&output, "nft")?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn ip_route_table_output(family: &str) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(ip_command()?)
        .args([family, "route", "show", "table", TPROXY_ROUTE_TABLE])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    if output.status.success() {
        return Ok(String::from_utf8_lossy(&output.stdout).into_owned());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.contains("FIB table does not exist") {
        return Ok(String::new());
    }
    Err(e2e_error(format!(
        "ip route show table failed with {}: {stderr}",
        output.status
    ))
    .into())
}

fn ip_output<const N: usize>(
    args: [&str; N],
    name: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new(ip_command()?)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;
    ensure_command_success(&output, name)?;
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn ip<const N: usize>(args: [&str; N]) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(ip_command()?).args(args).output()?;
    ensure_command_success(&output, "ip")
}

fn ensure_command_success(
    output: &std::process::Output,
    name: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if output.status.success() {
        Ok(())
    } else {
        Err(e2e_error(format!(
            "{name} failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ))
        .into())
    }
}

fn wait_with_timeout(
    mut child: Child,
    timeout: Duration,
) -> Result<std::process::Output, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            return Ok(child.wait_with_output()?);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(e2e_error(format!(
                "client command timed out after {}ms",
                timeout.as_millis()
            ))
            .into());
        }
        thread::sleep(Duration::from_millis(20));
    }
}

fn require_root() -> Result<(), Box<dyn std::error::Error>> {
    if rustix::process::geteuid().as_raw() == 0 {
        Ok(())
    } else {
        Err(e2e_error("transparent outbound proxy e2e must run as root").into())
    }
}

fn ip_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/sbin/ip", "/usr/bin/ip", "/sbin/ip", "/bin/ip"],
        "ip",
    )?)
}

fn nft_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/sbin/nft", "/usr/bin/nft", "/sbin/nft", "/bin/nft"],
        "nft",
    )?)
}

fn nc_command() -> Result<PathBuf, Box<dyn std::error::Error>> {
    Ok(trusted_system_command(
        ["/usr/bin/nc", "/bin/nc", "/usr/bin/netcat", "/bin/netcat"],
        "nc",
    )?)
}
