use std::{collections::BTreeSet, fs, path::Path, process::ExitCode};

use capture::CaptureEvent;
use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};
use probe_core::{
    CaptureProviderKind, CaptureSource, Direction, EventEnvelope, EventKind, HttpHeaders,
};
use storage::{FjallSpool, StoredEvent};

use super::{
    agent_admin::{assert_no_policy_runtime_errors, wait_for_agent_policy_progress},
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_capture_event,
        decode_envelope, e2e_error, ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{
        Http1LoopbackFixtureConfig, PlainHttp1LoopbackFixtureConfig, merge_run_results,
        spawn_agent, spawn_http1_loopback_fixture, start_http1_loopback_fixture,
        wait_for_agent_ready, wait_for_http1_loopback_fixture_exit,
        wait_for_http1_loopback_fixture_ready,
    },
};

const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-libpcap";
const INTERFACE: &str = "any";
const POLICY_ID: &str = "libpcap-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const EXPECTED_POLICY_VERSION: &str = "libpcap-e2e-policy@e2e";
const REQUESTS: usize = 2;
const REQUEST_BODY_BYTES: usize = 96;
const RESPONSE_BODY_BYTES: usize = 48;
const WRITE_CHUNKS: usize = 3;
const POST_EXCHANGE_DELAY_MS: u64 = 500;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e libpcap loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent", "e2e-fixture"])?;
    let root = create_temp_root("libpcap-loopback")?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e libpcap loopback passed");
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
    let fixture_ready_path = root.join("fixture.ready");
    let fixture_start_path = root.join("fixture.start");
    let agent_ready_socket_path = root.join("agent.ready.sock");
    let admin_socket_path = root.join("admin.sock");
    let policy_path = root.join("libpcap-e2e-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let supervisor = ChildSupervisor::new()?;
    write_policy_bundle(&policy_path)?;
    let mut fixture = supervisor.watch(
        spawn_http1_loopback_fixture(&fixture_ready_path, &fixture_start_path, fixture_config())?,
        "fixture",
    );
    let fixture_ready =
        wait_for_http1_loopback_fixture_ready(fixture.child_mut(), &fixture_ready_path)?;
    write_agent_config(
        &config_path,
        &policy_path,
        &spool_path,
        &admin_socket_path,
        fixture_ready.listen_port,
    )?;
    let mut ready_signal = UnixSocketReadySignal::bind(agent_ready_socket_path)?;
    let mut agent = supervisor.watch(spawn_agent(&config_path, &ready_signal)?, "agent");
    wait_for_agent_ready(agent.child_mut(), &mut ready_signal)?;
    let expected_fixture_pid = fixture_ready.pid;
    start_http1_loopback_fixture(&fixture_start_path, &fixture_ready.start_nonce)?;
    let fixture_result = wait_for_http1_loopback_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    let progress_result = match &fixture_result {
        Ok(()) => wait_for_agent_policy_progress(
            agent.child_mut(),
            &admin_socket_path,
            expected_policy_alert_messages().len() as u64,
        ),
        Err(_) => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (&fixture_result, &agent_result) {
        (Ok(()), Ok(())) => assert_spool_outputs(&spool_path, expected_fixture_pid),
        _ => Ok(()),
    };
    merge_run_results(fixture_result, progress_result, agent_result, spool_result)?;

    Ok(())
}

fn fixture_config() -> PlainHttp1LoopbackFixtureConfig {
    PlainHttp1LoopbackFixtureConfig {
        shared: Http1LoopbackFixtureConfig {
            listen_port: None,
            requests: REQUESTS,
            request_body_bytes: REQUEST_BODY_BYTES,
            response_body_bytes: RESPONSE_BODY_BYTES,
            write_chunks: WRITE_CHUNKS,
            connect_write_delay_ms: 0,
            post_exchange_delay_ms: POST_EXCHANGE_DELAY_MS,
        },
        accept_read_delay_ms: 0,
        vector_first_payload_slice_bytes: None,
    }
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
  local prefix = "/traffic-probe-e2e/"
  if string.sub(target, 1, #prefix) == prefix then
    return probe.emit_alert("libpcap policy observed " .. target)
  end
end
"#,
    )
}

fn write_agent_config(
    path: &Path,
    policy_path: &Path,
    spool_path: &Path,
    admin_socket_path: &Path,
    listen_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-libpcap-agent".to_string(),
        config_version: "e2e-libpcap-loopback".to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::Libpcap;
    config.capture.libpcap.interface = Some(INTERFACE.to_string());
    config.capture.libpcap.bpf_filter = format!("tcp and port {listen_port}");
    config.capture.libpcap.read_timeout_ms = 100;
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.admin.enabled = true;
    config.admin.socket_path = admin_socket_path.to_path_buf();
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        source: probe_config::PolicySourceConfig::LocalDirectory {
            path: policy_path.to_path_buf(),
        },
        enabled: true,
        selector: None,
        ..PolicyConfig::default()
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_spool_outputs(
    spool_path: &Path,
    expected_fixture_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 256)?;
    if ingress.is_empty() {
        return Err(e2e_error("expected libpcap ingress records, got none").into());
    }
    assert_libpcap_ingress(&ingress)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_requests(&envelopes, expected_fixture_pid)?;
    assert_expected_policy_alerts(&envelopes)?;

    println!(
        "e2e libpcap loopback observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn assert_libpcap_ingress(events: &[StoredEvent]) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    let degraded_bytes = capture_events
        .iter()
        .filter(|event| {
            matches!(
                event,
                CaptureEvent::Bytes(bytes)
                    if bytes.origin.source() == CaptureSource::Libpcap
                        && bytes.degraded
                        && bytes
                            .degradation_reason
                            .as_deref()
                            .is_some_and(|reason| reason.contains("libpcap fallback"))
            )
        })
        .count();
    if degraded_bytes == 0 {
        return Err(e2e_error("missing degraded libpcap ingress bytes").into());
    }
    Ok(())
}

fn assert_expected_requests(
    envelopes: &[EventEnvelope],
    expected_fixture_pid: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = libpcap_http_request_targets(envelopes);
    let expected = expected_targets();
    if !observed.is_superset(&expected) {
        let event_summaries = libpcap_event_summaries(envelopes);
        return Err(e2e_error(format!(
            "missing libpcap HTTP request targets; expected at least {:?}, observed {:?}, libpcap events {:?}",
            expected, observed, event_summaries
        ))
        .into());
    }

    let attributed = attributed_libpcap_http_request_targets(envelopes, expected_fixture_pid);
    if attributed.is_superset(&expected) {
        return Ok(());
    }

    let observed_flows = envelopes
        .iter()
        .filter_map(|envelope| {
            let flow = envelope.flow()?;
            Some(format!(
                "{}:{} pid={} process={} confidence={}",
                flow.local.address,
                flow.local.port,
                flow.process.identity.pid,
                flow.process.name,
                flow.attribution_confidence
            ))
        })
        .collect::<BTreeSet<_>>();
    Err(e2e_error(format!(
        "missing attributed libpcap HTTP request targets; expected at least {:?}, attributed {:?}, observed flows {:?}, libpcap events {:?}",
        expected,
        attributed,
        observed_flows,
        libpcap_event_summaries(envelopes)
    ))
    .into())
}

fn libpcap_http_request_targets(envelopes: &[EventEnvelope]) -> BTreeSet<String> {
    envelopes
        .iter()
        .filter_map(|envelope| libpcap_inbound_post_request(envelope)?.target.clone())
        .collect()
}

fn libpcap_event_summaries(envelopes: &[EventEnvelope]) -> BTreeSet<String> {
    envelopes
        .iter()
        .filter(|envelope| {
            envelope.origin().source() == CaptureSource::Libpcap
                && envelope.origin().provider() == CaptureProviderKind::Libpcap
        })
        .map(libpcap_event_summary)
        .collect()
}

fn libpcap_event_summary(envelope: &EventEnvelope) -> String {
    let flow = envelope.flow();
    let process = flow
        .map(|flow| {
            format!(
                "pid={} process={} confidence={}",
                flow.process.identity.pid, flow.process.name, flow.attribution_confidence
            )
        })
        .unwrap_or_else(|| "provider".to_string());
    let endpoints = flow
        .map(|flow| {
            format!(
                "local={}:{} remote={}:{}",
                flow.local.address, flow.local.port, flow.remote.address, flow.remote.port
            )
        })
        .unwrap_or_default();
    let summary = match envelope.kind() {
        EventKind::HttpRequestHeaders(headers) => format!(
            "method={:?} target={:?}",
            headers.method.as_deref(),
            headers.target.as_deref()
        ),
        EventKind::HttpResponseHeaders(headers) => {
            format!("status={:?} reason={:?}", headers.status, headers.reason)
        }
        EventKind::HttpBodyChunk(chunk) => {
            format!("body offset={} bytes={}", chunk.offset, chunk.data.len())
        }
        EventKind::Gap(gap) => format!(
            "gap expected_offset={} next_offset={:?} reason={}",
            gap.expected_offset, gap.next_offset, gap.reason
        ),
        EventKind::ProtocolError(error) => format!("protocol_error {}", error.reason),
        other => other.name().to_string(),
    };
    let direction = envelope
        .kind()
        .direction()
        .map(|direction| format!(" direction={direction:?}"))
        .unwrap_or_default();
    format!(
        "{}{} {} {} {}",
        envelope.kind().name(),
        direction,
        process,
        endpoints,
        summary
    )
}

fn attributed_libpcap_http_request_targets(
    envelopes: &[EventEnvelope],
    expected_fixture_pid: u32,
) -> BTreeSet<String> {
    envelopes
        .iter()
        .filter_map(|envelope| {
            let headers = libpcap_inbound_post_request(envelope)?;
            let flow = envelope.flow()?;
            (flow.attribution_confidence > 0 && flow.process.identity.pid == expected_fixture_pid)
                .then(|| headers.target.clone())
                .flatten()
        })
        .collect()
}

fn libpcap_inbound_post_request(envelope: &EventEnvelope) -> Option<&HttpHeaders> {
    match envelope.kind() {
        EventKind::HttpRequestHeaders(headers)
            if envelope.origin().source() == CaptureSource::Libpcap
                && envelope.origin().provider() == CaptureProviderKind::Libpcap
                && headers.direction == Direction::Inbound
                && headers.method.as_deref() == Some("POST") =>
        {
            Some(headers)
        }
        _ => None,
    }
}

fn assert_expected_policy_alerts(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match envelope.kind() {
            EventKind::PolicyAlert(alert)
                if envelope.origin().source() == CaptureSource::Libpcap
                    && envelope.origin().provider() == CaptureProviderKind::Libpcap
                    && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION) =>
            {
                Some(alert.message.clone())
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = expected_targets()
        .into_iter()
        .map(expected_policy_alert_message)
        .collect::<BTreeSet<_>>();
    if observed.is_superset(&expected) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing libpcap policy alerts; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn expected_targets() -> BTreeSet<String> {
    (0..REQUESTS)
        .map(|request| format!("/traffic-probe-e2e/{request}"))
        .collect()
}

fn expected_policy_alert_messages() -> BTreeSet<String> {
    expected_targets()
        .into_iter()
        .map(expected_policy_alert_message)
        .collect()
}

fn expected_policy_alert_message(target: String) -> String {
    format!("libpcap policy observed {target}")
}
