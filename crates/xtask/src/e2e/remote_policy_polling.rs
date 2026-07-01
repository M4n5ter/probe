use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::Path,
    process::{Child, ExitCode},
    thread,
    time::{Duration, Instant},
};

use capture::{CaptureEvent, CapturedBytes, EnforcementEvidencePropagation};
use probe_config::{AgentConfig, CaptureSelection, PolicyConfig, PolicySourceConfig};
use probe_core::{
    AddressPort, CaptureOrigin, CaptureSource, Direction, EnforcementEvidence, EventKind,
    FlowContext, FlowIdentity, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
};
use storage::FjallSpool;

use super::{
    harness::{
        ChildSupervisor, HttpSourceServer, UnixSocketReadySignal, create_temp_root,
        decode_envelope, e2e_error, ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{
        spawn_agent, wait_for_agent_policy_alert_count_above,
        wait_for_agent_policy_alert_count_at_least, wait_for_agent_ready,
    },
};

const AGENT_ID: &str = "e2e-remote-policy-polling-agent";
const CONFIG_VERSION: &str = "e2e-remote-policy-polling";
const POLICY_ID: &str = "e2e-remote-policy-polling";
const OLD_POLICY_VERSION: &str = "old";
const NEW_POLICY_VERSION: &str = "new";
const OLD_ALERT_PREFIX: &str = "old remote polling observed ";
const NEW_ALERT_PREFIX: &str = "new remote polling observed ";
const OLD_CONNECTION_ID: &str = "xtask-e2e-remote-policy-polling-old";
const NEW_CONNECTION_ID: &str = "xtask-e2e-remote-policy-polling-new";
const OLD_REQUEST_TARGET: &str = "/remote-policy-polling/old";
const NEW_REQUEST_TARGET: &str = "/remote-policy-polling/new";
const BUNDLE_REQUEST_TARGET: &str = "/policies/e2e-remote-policy-polling";
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-remote-policy-polling";
const REMOTE_POLL_INTERVAL_MS: u64 = 50;
const POLICY_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const POLICY_REQUEST_INTERVAL: Duration = Duration::from_millis(25);
const REPLACEMENT_POLICY_REQUESTS: usize = 3;
const CAPTURE_EVENTS_PER_FLOW: usize = 3;
const FLOW_COUNT: usize = 2;
const EXPECTED_INGRESS_RECORDS: usize = CAPTURE_EVENTS_PER_FLOW * FLOW_COUNT;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e remote policy polling failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent"])?;
    let root = create_temp_root("remote-policy-polling")?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e remote policy polling passed");
            Ok(())
        }
        Err(error) => {
            eprintln!("e2e artifacts retained at {}", root.display());
            Err(error)
        }
    }
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("capture-events.jsonl");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let admin_socket_path = root.join("admin.sock");
    let agent_ready_socket_path = root.join("agent.ready.sock");

    fs::write(&feed_path, [])?;
    let policy_server = HttpSourceServer::spawn(
        BUNDLE_REQUEST_TARGET,
        "application/toml",
        bundle_document(OLD_POLICY_VERSION, OLD_ALERT_PREFIX),
    )?;
    write_agent_config(
        &config_path,
        &feed_path,
        &spool_path,
        &admin_socket_path,
        policy_server.endpoint(),
    )?;

    let supervisor = ChildSupervisor::new()?;
    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;

    append_http_request_flow(&feed_path, &old_case())?;
    let old_alert_count =
        wait_for_agent_policy_alert_count_at_least(agent.child_mut(), &admin_socket_path, 1)?;

    let requests_before_replace = policy_server.request_count();
    policy_server.replace_body(bundle_document(NEW_POLICY_VERSION, NEW_ALERT_PREFIX))?;
    // One old response may already be in flight when the fixture body changes.
    // The first new response can be written before the agent finishes compiling
    // and swapping the new policy. The next poll starts only after that reload
    // attempt completes because the poller is sequential.
    wait_for_policy_requests_after(
        agent.child_mut(),
        &policy_server,
        requests_before_replace,
        REPLACEMENT_POLICY_REQUESTS,
    )?;

    append_http_request_flow(&feed_path, &new_case())?;
    wait_for_agent_policy_alert_count_above(
        agent.child_mut(),
        &admin_socket_path,
        old_alert_count,
    )?;

    stop_running_child(agent.child_mut(), "agent")?;
    agent.unwatch();
    let policy_requests = policy_server.finish()?;
    if policy_requests <= requests_before_replace {
        return Err(e2e_error(format!(
            "remote policy poller did not request replacement bundle; before={requests_before_replace}, after={policy_requests}"
        ))
        .into());
    }
    assert_spool_outputs(&spool_path)?;

    println!("e2e remote policy polling observed {policy_requests} remote bundle request(s)");
    Ok(())
}

fn write_agent_config(
    path: &Path,
    feed_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    policy_endpoint: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: AGENT_ID.to_string(),
        config_version: CONFIG_VERSION.to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::CaptureEventFeed;
    config.capture.capture_event_feed.path = Some(feed_path.to_path_buf());
    config.capture.capture_event_feed.follow = Some(true);
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    config.policy_reload.poll_remote_bundles = true;
    config.policy_reload.remote_poll_interval_ms = REMOTE_POLL_INTERVAL_MS;
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        source: PolicySourceConfig::RemoteBundle {
            endpoint: policy_endpoint,
            max_body_bytes: Some(1024 * 1024),
        },
        enabled: true,
        selector: None,
        ..PolicyConfig::default()
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn bundle_document(version: &str, alert_prefix: &str) -> String {
    format!(
        r#"source = '''
function on_http_request_headers(event)
  return probe.emit_alert("{alert_prefix}" .. event.kind.target)
end
'''

[manifest]
id = "{POLICY_ID}"
version = "{version}"
hooks = ["on_http_request_headers"]
"#
    )
}

fn append_http_request_flow(
    path: &Path,
    case: &RemotePolicyPollingCase,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().append(true).open(path)?;
    for event in case.capture_events() {
        let mut line = serde_json::to_string(&event)?;
        line.push('\n');
        file.write_all(line.as_bytes())?;
    }
    file.flush()?;
    Ok(())
}

fn wait_for_policy_requests_after(
    agent: &mut Child,
    policy_server: &HttpSourceServer,
    previous_request_count: usize,
    expected_additional_requests: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_request_count = previous_request_count + expected_additional_requests;
    let deadline = Instant::now() + POLICY_REQUEST_TIMEOUT;
    loop {
        if policy_server.request_count() >= expected_request_count {
            return Ok(());
        }
        if let Some(status) = agent.try_wait()? {
            return Err(e2e_error(format!(
                "agent exited with {status} before remote policy polling requested the replacement bundle"
            ))
            .into());
        }
        if Instant::now() >= deadline {
            return Err(e2e_error(format!(
                "timed out waiting for remote policy requests to reach {expected_request_count}; previous={previous_request_count}"
            ))
            .into());
        }
        thread::sleep(POLICY_REQUEST_INTERVAL);
    }
}

#[derive(Debug, Clone)]
struct RemotePolicyPollingCase {
    connection_id: &'static str,
    target: &'static str,
    local_port: u16,
    remote_port: u16,
    socket_cookie: u64,
    pid: u32,
    start_time_ticks: u64,
    process_name: &'static str,
    exe_path: &'static str,
    cmdline_hash: &'static str,
}

impl RemotePolicyPollingCase {
    fn capture_events(&self) -> [CaptureEvent; 3] {
        let flow = self.flow();
        [
            CaptureEvent::ConnectionOpened {
                timestamp: timestamp(1),
                flow: flow.clone(),
                origin: capture_origin(),
            },
            CaptureEvent::Bytes(CapturedBytes {
                timestamp: timestamp(2),
                flow: flow.clone(),
                origin: capture_origin(),
                direction: Direction::Outbound,
                stream_offset: 0,
                bytes: self.request_bytes().into(),
                attribution_confidence: 100,
                degraded: false,
                degradation_reason: None,
                enforcement_evidence: EnforcementEvidence::default(),
                enforcement_evidence_propagation: EnforcementEvidencePropagation::Event,
            }),
            CaptureEvent::ConnectionClosed {
                timestamp: timestamp(3),
                flow,
                origin: capture_origin(),
            },
        ]
    }

    fn flow(&self) -> FlowContext {
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: self.local_port,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: self.remote_port,
        };
        let process = ProcessContext {
            identity: ProcessIdentity {
                pid: self.pid,
                tgid: self.pid,
                start_time_ticks: self.start_time_ticks,
                boot_id: "boot".to_string(),
                exe_path: self.exe_path.to_string(),
                cmdline_hash: self.cmdline_hash.to_string(),
                uid: 1000,
                gid: 1000,
                cgroup: None,
                systemd_service: None,
                container_id: None,
                runtime_hint: None,
            },
            name: self.process_name.to_string(),
            cmdline: vec![self.process_name.to_string()],
        };
        FlowContext {
            id: FlowIdentity(format!("external_plaintext_feed:{}", self.connection_id)),
            process,
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: Some(self.socket_cookie),
            attribution_confidence: 100,
        }
    }

    fn request_bytes(&self) -> Vec<u8> {
        format!(
            "GET {} HTTP/1.1\r\nHost: remote-policy-polling.e2e.test\r\n\r\n",
            self.target
        )
        .into_bytes()
    }

    fn expected_flow_id(&self) -> String {
        format!("external_plaintext_feed:{}", self.connection_id)
    }
}

fn old_case() -> RemotePolicyPollingCase {
    RemotePolicyPollingCase {
        connection_id: OLD_CONNECTION_ID,
        target: OLD_REQUEST_TARGET,
        local_port: 53_010,
        remote_port: 8_090,
        socket_cookie: 3_101,
        pid: 701,
        start_time_ticks: 1_701,
        process_name: "traffic-probe-e2e-remote-policy-old",
        exe_path: "/usr/bin/traffic-probe-e2e-remote-policy-old",
        cmdline_hash: "remote-policy-polling-old-hash",
    }
}

fn new_case() -> RemotePolicyPollingCase {
    RemotePolicyPollingCase {
        connection_id: NEW_CONNECTION_ID,
        target: NEW_REQUEST_TARGET,
        local_port: 53_011,
        remote_port: 8_090,
        socket_cookie: 3_102,
        pid: 702,
        start_time_ticks: 1_702,
        process_name: "traffic-probe-e2e-remote-policy-new",
        exe_path: "/usr/bin/traffic-probe-e2e-remote-policy-new",
        cmdline_hash: "remote-policy-polling-new-hash",
    }
}

fn capture_origin() -> CaptureOrigin {
    CaptureOrigin::from_source(CaptureSource::ExternalPlaintextFeed)
}

fn timestamp(monotonic_ns: u64) -> Timestamp {
    Timestamp {
        monotonic_ns,
        wall_time_unix_ns: i64::try_from(monotonic_ns).unwrap_or(i64::MAX),
    }
}

fn assert_spool_outputs(spool_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 16)?;
    if ingress.len() != EXPECTED_INGRESS_RECORDS {
        return Err(e2e_error(format!(
            "expected {EXPECTED_INGRESS_RECORDS} remote policy polling ingress records, observed {}",
            ingress.len()
        ))
        .into());
    }

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 128)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;

    let alerts = collect_policy_alerts(&envelopes);
    let expected = expected_policy_alerts();
    if alerts != expected {
        return Err(e2e_error(format!(
            "unexpected remote polling policy alerts; expected {expected:?}, observed {alerts:?}"
        ))
        .into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PolicyAlertFact {
    flow_id: String,
    policy_version: String,
    message: String,
}

fn collect_policy_alerts(envelopes: &[probe_core::EventEnvelope]) -> BTreeSet<PolicyAlertFact> {
    envelopes
        .iter()
        .filter_map(|envelope| {
            let EventKind::PolicyAlert(alert) = envelope.kind() else {
                return None;
            };
            Some(PolicyAlertFact {
                flow_id: envelope.flow()?.id.0.clone(),
                policy_version: envelope.policy_version()?.to_string(),
                message: alert.message.clone(),
            })
        })
        .filter(|fact| {
            fact.flow_id == old_case().expected_flow_id()
                || fact.flow_id == new_case().expected_flow_id()
        })
        .collect()
}

fn expected_policy_alerts() -> BTreeSet<PolicyAlertFact> {
    [
        PolicyAlertFact {
            flow_id: old_case().expected_flow_id(),
            policy_version: format!("{POLICY_ID}@{OLD_POLICY_VERSION}"),
            message: format!("{OLD_ALERT_PREFIX}{OLD_REQUEST_TARGET}"),
        },
        PolicyAlertFact {
            flow_id: new_case().expected_flow_id(),
            policy_version: format!("{POLICY_ID}@{NEW_POLICY_VERSION}"),
            message: format!("{NEW_ALERT_PREFIX}{NEW_REQUEST_TARGET}"),
        },
    ]
    .into_iter()
    .collect()
}

fn assert_no_policy_runtime_errors(
    envelopes: &[probe_core::EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes
        .iter()
        .any(|envelope| matches!(envelope.kind(), EventKind::PolicyRuntimeError(_)))
    {
        return Err(e2e_error("remote policy polling produced a policy runtime error").into());
    }
    Ok(())
}
