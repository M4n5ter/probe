use std::{
    fs,
    io::{ErrorKind, Read, Write},
    net::{TcpListener, TcpStream},
    path::Path,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use capture::CaptureEvent;
use probe_config::{EnforcementPolicyManifest, EnforcementPolicySourceConfig};
use probe_core::{
    Action, CaptureProviderKind, CaptureSource, Direction, EnforcementMode, EnforcementOutcome,
    EventEnvelope, EventKind, ProcessSelector, ProtectiveActionProfile, Selector, TrafficSelector,
    VerdictScope,
};
use storage::{FjallSpool, StoredEvent};

use super::harness::{
    decode_capture_event, decode_envelope, e2e_error, run_agent_with_max_events, run_with_temp_root,
};
use super::plaintext_scenario::{
    PlaintextFeedCase, PlaintextFeedRecord, PlaintextFlow, PlaintextProcess,
};

const FEED_EVENTS_PER_CASE: usize = 3;
const EXPORT_EVENTS_PER_CASE: usize = 5;
const CASE_COUNT: usize = 4;
const FEED_EVENT_COUNT: usize = FEED_EVENTS_PER_CASE * CASE_COUNT;
const EXPORT_EVENT_COUNT: usize = EXPORT_EVENTS_PER_CASE * CASE_COUNT;
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e";
const AGENT_ID: &str = "e2e-remote-enforcement-agent";
const CONFIG_VERSION: &str = "e2e-remote-enforcement-policy";
const ALLOWED_CONNECTION_ID: &str = "xtask-e2e-remote-enforcement-allowed";
const MANIFEST_MISS_CONNECTION_ID: &str = "xtask-e2e-remote-enforcement-manifest-miss";
const CONFIG_MISS_CONNECTION_ID: &str = "xtask-e2e-remote-enforcement-config-miss";
const PROFILE_MISS_CONNECTION_ID: &str = "xtask-e2e-remote-enforcement-profile-miss";
const PROCESS_NAME: &str = "sssa-e2e-remote-enforcement";
const CONFIG_ONLY_PROCESS_NAME: &str = "sssa-e2e-config-only-enforcement";
const ALLOWED_LOCAL_PORT: u16 = 52_200;
const MANIFEST_MISS_LOCAL_PORT: u16 = 52_201;
const CONFIG_MISS_LOCAL_PORT: u16 = 52_202;
const PROFILE_MISS_LOCAL_PORT: u16 = 52_203;
const REMOTE_PORT: u16 = 8_080;
const MANIFEST_MISS_REMOTE_PORT: u16 = 8_081;
const POLICY_ID: &str = "e2e-remote-enforcement-policy";
const POLICY_VERSION: &str = "e2e";
const MANIFEST_ID: &str = "e2e-managed-enforcement";
const MANIFEST_VERSION: &str = "e2e";
const ALLOWED_REQUEST_TARGET: &str = "/remote-enforcement/allowed";
const MANIFEST_MISS_REQUEST_TARGET: &str = "/remote-enforcement/manifest-miss";
const CONFIG_MISS_REQUEST_TARGET: &str = "/remote-enforcement/config-miss";
const PROFILE_MISS_REQUEST_TARGET: &str = "/remote-enforcement/profile-miss";
const POLICY_REASON_PREFIX: &str = "remote manifest scoped protection";
const MANIFEST_REQUEST_TARGET: &str = "/enforcement";
const REQUEST_IO_TIMEOUT: Duration = Duration::from_secs(3);

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e remote enforcement policy failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("remote-enforcement-policy", run_at)?;
    println!("e2e remote enforcement policy passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("feed.jsonl");
    let policy_path = root.join("e2e-remote-enforcement-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let cases = remote_cases();
    write_feed(&cases, &feed_path)?;
    write_policy_bundle(&policy_path)?;
    let manifest_server = ManifestServer::spawn(toml::to_string(&enforcement_manifest()?)?)?;

    let mut config = cases[0].feed.agent_config_with_policy(
        feed_path,
        policy_path,
        spool_path.clone(),
        POLICY_ID,
    );
    config.export.worker.enabled = false;
    config.enforcement.mode = EnforcementMode::DryRun;
    config.enforcement.selector = Some(config_selector());
    config.enforcement.policy.source = EnforcementPolicySourceConfig::Remote {
        endpoint: manifest_server.endpoint(),
    };
    fs::write(&config_path, toml::to_string(&config)?)?;

    run_agent_with_max_events(&config_path, FEED_EVENT_COUNT)?;
    let manifest_requests = manifest_server.finish()?;
    if manifest_requests != 1 {
        return Err(e2e_error(format!(
            "expected exactly one remote enforcement manifest request, got {manifest_requests}"
        ))
        .into());
    }
    assert_spool_outputs(&spool_path, &cases)?;

    Ok(())
}

fn remote_cases() -> Vec<RemoteEnforcementCase> {
    vec![
        RemoteEnforcementCase::new(
            "allowed",
            ALLOWED_CONNECTION_ID,
            ALLOWED_REQUEST_TARGET,
            PlaintextFlow::new(
                ALLOWED_LOCAL_PORT,
                REMOTE_PORT,
                2_101,
                PlaintextProcess::new(
                    512,
                    901,
                    PROCESS_NAME,
                    "/usr/bin/sssa-e2e-remote-enforcement",
                    "remote-enforcement-hash",
                ),
            ),
            Action::Deny,
            DecisionExpectation::DryRun,
        ),
        RemoteEnforcementCase::new(
            "manifest miss",
            MANIFEST_MISS_CONNECTION_ID,
            MANIFEST_MISS_REQUEST_TARGET,
            PlaintextFlow::new(
                MANIFEST_MISS_LOCAL_PORT,
                MANIFEST_MISS_REMOTE_PORT,
                2_102,
                PlaintextProcess::new(
                    513,
                    902,
                    CONFIG_ONLY_PROCESS_NAME,
                    "/usr/bin/sssa-e2e-config-only-enforcement",
                    "config-only-enforcement-hash",
                ),
            ),
            Action::Deny,
            DecisionExpectation::SelectorMiss,
        ),
        RemoteEnforcementCase::new(
            "config miss",
            CONFIG_MISS_CONNECTION_ID,
            CONFIG_MISS_REQUEST_TARGET,
            PlaintextFlow::new(
                CONFIG_MISS_LOCAL_PORT,
                REMOTE_PORT,
                2_103,
                PlaintextProcess::new(
                    514,
                    903,
                    PROCESS_NAME,
                    "/usr/bin/sssa-e2e-remote-enforcement",
                    "remote-enforcement-hash",
                ),
            ),
            Action::Deny,
            DecisionExpectation::SelectorMiss,
        ),
        RemoteEnforcementCase::new(
            "profile miss",
            PROFILE_MISS_CONNECTION_ID,
            PROFILE_MISS_REQUEST_TARGET,
            PlaintextFlow::new(
                PROFILE_MISS_LOCAL_PORT,
                REMOTE_PORT,
                2_104,
                PlaintextProcess::new(
                    515,
                    904,
                    PROCESS_NAME,
                    "/usr/bin/sssa-e2e-remote-enforcement",
                    "remote-enforcement-hash",
                ),
            ),
            Action::Reset,
            DecisionExpectation::UnsupportedProfile,
        ),
    ]
}

fn write_feed(
    cases: &[RemoteEnforcementCase],
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut content = String::new();
    for case in cases {
        content.push_str(&case.feed.feed_records_jsonl([
            PlaintextFeedRecord::connection_opened(),
            PlaintextFeedRecord::bytes(Direction::Outbound, 0, request_bytes(case.target)),
            PlaintextFeedRecord::connection_closed(),
        ])?);
    }
    fs::write(path, content)?;
    Ok(())
}

fn request_bytes(target: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nHost: remote-policy.e2e.test\r\n\r\n").into_bytes()
}

struct RemoteEnforcementCase {
    label: &'static str,
    target: &'static str,
    feed: PlaintextFeedCase,
    requested_action: Action,
    decision: DecisionExpectation,
}

impl RemoteEnforcementCase {
    fn new(
        label: &'static str,
        connection_id: &'static str,
        target: &'static str,
        flow: PlaintextFlow,
        requested_action: Action,
        decision: DecisionExpectation,
    ) -> Self {
        Self {
            label,
            target,
            feed: PlaintextFeedCase::new(AGENT_ID, CONFIG_VERSION, connection_id, flow),
            requested_action,
            decision,
        }
    }

    fn expected_reason(&self) -> String {
        format!("{POLICY_REASON_PREFIX} {}", self.target)
    }
}

#[derive(Clone, Copy)]
enum DecisionExpectation {
    DryRun,
    SelectorMiss,
    UnsupportedProfile,
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
        format!(
            r#"
function on_http_request_headers(event)
  local action = "deny"
  if event.kind.target == "{PROFILE_MISS_REQUEST_TARGET}" then
    action = "reset"
  end
  return probe.verdict({{
action = action,
scope = "request",
reason = "{POLICY_REASON_PREFIX} " .. event.kind.target,
confidence = 100,
  }})
end
"#
        ),
    )
}

fn enforcement_manifest() -> Result<EnforcementPolicyManifest, Box<dyn std::error::Error>> {
    Ok(EnforcementPolicyManifest {
        id: MANIFEST_ID.to_string(),
        version: MANIFEST_VERSION.to_string(),
        selector: Some(Selector::term(
            ProcessSelector {
                names: vec![PROCESS_NAME.to_string()],
                ..ProcessSelector::default()
            },
            TrafficSelector {
                remote_ports: vec![REMOTE_PORT],
                directions: vec![Direction::Outbound],
                ..TrafficSelector::default()
            },
        )),
        protective_actions: ProtectiveActionProfile::new([Action::Deny])?,
    })
}

fn config_selector() -> Selector {
    Selector::term(
        ProcessSelector {
            names: vec![
                PROCESS_NAME.to_string(),
                CONFIG_ONLY_PROCESS_NAME.to_string(),
            ],
            ..ProcessSelector::default()
        },
        TrafficSelector {
            local_ports: vec![
                ALLOWED_LOCAL_PORT,
                MANIFEST_MISS_LOCAL_PORT,
                PROFILE_MISS_LOCAL_PORT,
            ],
            directions: vec![Direction::Outbound],
            ..TrafficSelector::default()
        },
    )
}

fn assert_spool_outputs(
    spool_path: &Path,
    cases: &[RemoteEnforcementCase],
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 16)?;
    if ingress.len() != FEED_EVENT_COUNT {
        return Err(e2e_error(format!(
            "expected {FEED_EVENT_COUNT} ingress records, got {}",
            ingress.len()
        ))
        .into());
    }
    assert_ingress_events(&ingress, cases)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 64)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    if envelopes.len() != EXPORT_EVENT_COUNT {
        return Err(e2e_error(format!(
            "expected {EXPORT_EVENT_COUNT} export records, got {}",
            envelopes.len()
        ))
        .into());
    }
    assert_exports(&envelopes, cases)?;

    println!(
        "e2e remote enforcement policy observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn assert_ingress_events(
    events: &[StoredEvent],
    cases: &[RemoteEnforcementCase],
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    for case in cases {
        assert_single_ingress_event(&capture_events, case, "connection_opened", |event| {
            matches!(
                event,
                CaptureEvent::ConnectionOpened { origin, flow, .. }
                    if is_plaintext_feed_origin(*origin)
                        && flow.id.0 == case.feed.expected_flow_id()
            )
        })?;
        assert_single_ingress_event(&capture_events, case, "HTTP request bytes", |event| {
            matches!(
                event,
                CaptureEvent::Bytes(bytes)
                    if is_plaintext_feed_origin(bytes.origin)
                        && bytes.flow.id.0 == case.feed.expected_flow_id()
                        && bytes.direction == Direction::Outbound
                        && bytes.stream_offset == 0
                        && bytes.bytes.as_ref() == request_bytes(case.target).as_slice()
            )
        })?;
        assert_single_ingress_event(&capture_events, case, "connection_closed", |event| {
            matches!(
                event,
                CaptureEvent::ConnectionClosed { origin, flow, .. }
                    if is_plaintext_feed_origin(*origin)
                        && flow.id.0 == case.feed.expected_flow_id()
            )
        })?;
    }
    Ok(())
}

fn assert_exports(
    envelopes: &[EventEnvelope],
    cases: &[RemoteEnforcementCase],
) -> Result<(), Box<dyn std::error::Error>> {
    let expected_policy_version = expected_policy_version();
    for case in cases {
        let expected_reason = case.expected_reason();
        let label = format!("{} HTTP request", case.label);
        assert_single_event(envelopes, case, &label, |envelope| {
            matches!(
                envelope.kind(),
                EventKind::HttpRequestHeaders(headers)
                    if headers.direction == Direction::Outbound
                        && headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(case.target)
            )
        })?;
        let label = format!("{} policy verdict", case.label);
        assert_single_event(envelopes, case, &label, |envelope| {
            envelope.policy_version() == Some(expected_policy_version.as_str())
                && matches!(
                    envelope.kind(),
                    EventKind::PolicyVerdict(verdict)
                        if verdict.action == case.requested_action
                            && verdict.scope == VerdictScope::Request
                            && verdict.reason == expected_reason
                            && verdict.confidence == 100
                )
        })?;
        let label = format!("{} enforcement decision", case.label);
        assert_single_event(envelopes, case, &label, |envelope| {
            envelope.policy_version() == Some(expected_policy_version.as_str())
                && matches!(
                    envelope.kind(),
                    EventKind::EnforcementDecision(decision)
                        if decision_matches(decision, case, expected_reason.as_str())
                )
        })?;
        let label = format!("{} connection opened", case.label);
        assert_single_event(envelopes, case, &label, |envelope| {
            matches!(envelope.kind(), EventKind::ConnectionOpened)
        })?;
        let label = format!("{} connection closed", case.label);
        assert_single_event(envelopes, case, &label, |envelope| {
            matches!(envelope.kind(), EventKind::ConnectionClosed)
        })?;
    }
    if envelopes.iter().any(|envelope| {
        matches!(
            envelope.kind(),
            EventKind::PolicyRuntimeError(_) | EventKind::ProtocolError(_)
        )
    }) {
        return Err(e2e_error("remote enforcement policy E2E produced an error event").into());
    }
    Ok(())
}

fn assert_single_ingress_event(
    events: &[CaptureEvent],
    case: &RemoteEnforcementCase,
    label: &str,
    matches_event: impl Fn(&CaptureEvent) -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let matching_positions = events
        .iter()
        .enumerate()
        .filter_map(|(position, event)| matches_event(event).then_some(position))
        .collect::<Vec<_>>();
    let [_position] = matching_positions.as_slice() else {
        return Err(e2e_error(format!(
            "expected exactly one {} ingress {label} event, got {} at positions {matching_positions:?}",
            case.label,
            matching_positions.len()
        ))
        .into());
    };
    Ok(())
}

fn is_plaintext_feed_origin(origin: probe_core::CaptureOrigin) -> bool {
    origin.source() == CaptureSource::ExternalPlaintextFeed
        && origin.provider() == CaptureProviderKind::Plaintext
}

fn decision_matches(
    decision: &probe_core::EnforcementDecision,
    case: &RemoteEnforcementCase,
    expected_reason: &str,
) -> bool {
    decision.mode == EnforcementMode::DryRun
        && decision.requested_action == case.requested_action
        && decision.effective_action == Action::Observe
        && decision.scope == VerdictScope::Request
        && decision.reason.contains(expected_reason)
        && match case.decision {
            DecisionExpectation::DryRun => {
                decision.outcome == EnforcementOutcome::DryRun
                    && decision.selector_matched
                    && decision.reason.contains("dry-run")
            }
            DecisionExpectation::SelectorMiss => {
                decision.outcome == EnforcementOutcome::SelectorMiss
                    && !decision.selector_matched
                    && decision
                        .reason
                        .contains("enforcement selector did not match")
            }
            DecisionExpectation::UnsupportedProfile => {
                decision.outcome == EnforcementOutcome::Unsupported
                    && decision.selector_matched
                    && decision
                        .reason
                        .contains("configured enforcement profile does not allow")
            }
        }
}

fn assert_single_event(
    envelopes: &[EventEnvelope],
    case: &RemoteEnforcementCase,
    label: &str,
    matches_event: impl Fn(&EventEnvelope) -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let matching_positions = envelopes
        .iter()
        .enumerate()
        .filter_map(|(position, envelope)| {
            (case.feed.matches_export_flow(envelope) && matches_event(envelope)).then_some(position)
        })
        .collect::<Vec<_>>();
    let [_position] = matching_positions.as_slice() else {
        return Err(e2e_error(format!(
            "expected exactly one {label} export event, got {} at positions {matching_positions:?}",
            matching_positions.len()
        ))
        .into());
    };
    Ok(())
}

fn expected_policy_version() -> String {
    format!("{POLICY_ID}@{POLICY_VERSION}")
}

struct ManifestServer {
    endpoint: String,
    request_count: Arc<AtomicUsize>,
    stop_requested: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<Result<(), String>>>,
}

impl ManifestServer {
    fn spawn(body: String) -> Result<Self, Box<dyn std::error::Error>> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let endpoint = format!(
            "http://{}{}",
            listener.local_addr()?,
            MANIFEST_REQUEST_TARGET
        );
        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_for_thread = Arc::clone(&request_count);
        let stop_requested = Arc::new(AtomicBool::new(false));
        let stop_requested_for_thread = Arc::clone(&stop_requested);
        let handle = thread::spawn(move || {
            while !stop_requested_for_thread.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(accepted) => accepted,
                    Err(error) if error.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(error) => return Err(error.to_string()),
                };
                stream
                    .set_read_timeout(Some(REQUEST_IO_TIMEOUT))
                    .map_err(|error| error.to_string())?;
                stream
                    .set_write_timeout(Some(REQUEST_IO_TIMEOUT))
                    .map_err(|error| error.to_string())?;
                let (method, target) = read_manifest_request(&mut stream)?;
                if method != "GET" || target != MANIFEST_REQUEST_TARGET {
                    let response =
                        "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
                    stream
                        .write_all(response.as_bytes())
                        .map_err(|error| error.to_string())?;
                    return Err(format!("unexpected manifest request {method} {target}"));
                }
                let response = manifest_response(&body);
                stream
                    .write_all(response.as_bytes())
                    .map_err(|error| error.to_string())?;
                request_count_for_thread.fetch_add(1, Ordering::Relaxed);
            }
            Ok(())
        });

        Ok(Self {
            endpoint,
            request_count,
            stop_requested,
            handle: Some(handle),
        })
    }

    fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    fn finish(mut self) -> Result<usize, Box<dyn std::error::Error>> {
        self.stop_and_join()
            .map_err(|error| e2e_error(format!("manifest server failed: {error}")))?;
        Ok(self.request_count.load(Ordering::Relaxed))
    }

    fn stop_and_join(&mut self) -> Result<(), String> {
        self.stop_requested.store(true, Ordering::Relaxed);
        let Some(handle) = self.handle.take() else {
            return Ok(());
        };
        handle
            .join()
            .map_err(|_| "manifest server thread panicked".to_string())?
    }
}

impl Drop for ManifestServer {
    fn drop(&mut self) {
        if let Err(error) = self.stop_and_join() {
            eprintln!("manifest server cleanup failed: {error}");
        }
    }
}

fn read_manifest_request(stream: &mut TcpStream) -> Result<(String, String), String> {
    let mut bytes = Vec::new();
    loop {
        let mut buffer = [0; 1024];
        let read = stream
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            return Err("connection closed before manifest request headers completed".to_string());
        }
        bytes.extend_from_slice(&buffer[..read]);
        if header_end(&bytes).is_some() {
            break;
        }
    }
    let headers = String::from_utf8_lossy(&bytes);
    let line = headers
        .lines()
        .next()
        .ok_or_else(|| "manifest request is missing request line".to_string())?;
    let mut parts = line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "manifest request line is missing method".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "manifest request line is missing target".to_string())?;
    let version = parts
        .next()
        .ok_or_else(|| "manifest request line is missing version".to_string())?;
    if !version.starts_with("HTTP/") || parts.next().is_some() {
        return Err(format!("invalid manifest request line {line}"));
    }
    Ok((method.to_string(), target.to_string()))
}

fn manifest_response(body: &str) -> String {
    format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/toml\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    )
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes.windows(4).position(|window| window == b"\r\n\r\n")
}
