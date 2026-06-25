use std::{fs, path::Path, process::ExitCode};

use capture::CaptureEvent;
use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};
use probe_core::{
    CaptureProviderKind, CaptureSource, Direction, EventEnvelope, EventKind, WebSocketOpcode,
};
use storage::{FjallSpool, StoredEvent};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_capture_event,
        decode_envelope, e2e_error, ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{
        WebSocketLoopbackFixtureConfig, assert_no_policy_runtime_errors, merge_run_results,
        spawn_agent, spawn_websocket_loopback_fixture, start_http1_loopback_fixture,
        wait_for_agent_policy_progress, wait_for_agent_ready, wait_for_http1_loopback_fixture_exit,
        wait_for_http1_loopback_fixture_ready,
    },
    plaintext_assertions::has_header,
    websocket_expectations::{
        FRAME_PAYLOAD_BYTES, FRAME_PAYLOAD_FINGERPRINT, FRAME_PAYLOAD_LEN, REQUEST_TARGET,
        RFC_SAMPLE_WEBSOCKET_ACCEPT, SUBPROTOCOL,
    },
};

const CONTEXT: &str = "libpcap websocket";
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e-libpcap-websocket";
const INTERFACE: &str = "any";
const POLICY_ID: &str = "libpcap-websocket-e2e-policy";
const POLICY_VERSION: &str = "e2e";
const EXPECTED_POLICY_VERSION: &str = "libpcap-websocket-e2e-policy@e2e";
const HANDOFF_ALERT: &str = "libpcap websocket handoff /chat chat";
const FRAME_ALERT: &str = "libpcap websocket frame text 2";

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e libpcap websocket loopback failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    ensure_e2e_packages_built(["agent", "e2e-fixture"])?;
    let root = create_temp_root("libpcap-websocket-loopback")?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e libpcap websocket loopback passed");
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
    let policy_path = root.join("libpcap-websocket-e2e-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let supervisor = ChildSupervisor::new()?;
    write_policy_bundle(&policy_path)?;
    let mut fixture = supervisor.watch(
        spawn_websocket_loopback_fixture(
            &fixture_ready_path,
            &fixture_start_path,
            fixture_config(),
        )?,
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
    start_http1_loopback_fixture(&fixture_start_path, &fixture_ready.start_nonce)?;
    let fixture_result = wait_for_http1_loopback_fixture_exit(fixture.child_mut());
    fixture.unwatch();
    let progress_result = match &fixture_result {
        Ok(()) => wait_for_agent_policy_progress(agent.child_mut(), &admin_socket_path, 2),
        Err(_) => Ok(()),
    };
    let agent_result = stop_running_child(agent.child_mut(), "agent");
    agent.unwatch();
    let spool_result = match (&fixture_result, &agent_result) {
        (Ok(()), Ok(())) => assert_spool_outputs(&spool_path),
        _ => Ok(()),
    };
    merge_run_results(fixture_result, progress_result, agent_result, spool_result)?;

    Ok(())
}

fn fixture_config() -> WebSocketLoopbackFixtureConfig {
    WebSocketLoopbackFixtureConfig {
        listen_port: None,
        connections: 1,
        frame_payload_bytes: FRAME_PAYLOAD_BYTES,
        write_chunks: 2,
        connect_write_delay_ms: 0,
        post_exchange_delay_ms: 0,
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
hooks = ["on_websocket_handoff", "on_websocket_frame"]
"#
        ),
    )?;
    fs::write(
        path.join("main.lua"),
        r#"
function on_websocket_handoff(event)
  return probe.emit_alert("libpcap websocket handoff " .. event.kind.target .. " " .. event.kind.subprotocol)
end

function on_websocket_frame(event)
  return probe.emit_alert(
    "libpcap websocket frame " .. event.kind.opcode.kind .. " " .. tostring(event.kind.payload_len)
  )
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
        agent_id: "e2e-libpcap-websocket-agent".to_string(),
        config_version: "e2e-libpcap-websocket-loopback".to_string(),
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
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_spool_outputs(spool_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 256)?;
    if ingress.is_empty() {
        return Err(e2e_error("expected libpcap websocket ingress records, got none").into());
    }
    assert_libpcap_ingress(&ingress)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_websocket_exports(&envelopes)?;

    println!(
        "e2e libpcap websocket loopback observed {} ingress records and {} export records",
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
                        && bytes.origin.provider() == CaptureProviderKind::Libpcap
                        && bytes.degraded
                        && bytes
                            .degradation_reason
                            .as_deref()
                            .is_some_and(|reason| reason.contains("libpcap fallback"))
            )
        })
        .count();
    if degraded_bytes == 0 {
        return Err(e2e_error("missing degraded libpcap websocket ingress bytes").into());
    }
    Ok(())
}

fn assert_websocket_exports(envelopes: &[EventEnvelope]) -> Result<(), Box<dyn std::error::Error>> {
    assert_has_event(envelopes, "HTTP upgrade request", |envelope| {
        matches!(
            envelope.kind(),
            EventKind::HttpRequestHeaders(headers)
                if is_libpcap_event(envelope)
                    && headers.direction == Direction::Outbound
                    && headers.method.as_deref() == Some("GET")
                    && headers.target.as_deref() == Some(REQUEST_TARGET)
        )
    })?;
    assert_has_event(envelopes, "HTTP 101 response", |envelope| {
        matches!(
            envelope.kind(),
            EventKind::HttpResponseHeaders(headers)
                if is_libpcap_event(envelope)
                    && headers.direction == Direction::Inbound
                    && headers.status == Some(101)
                    && has_header(
                        &headers.headers,
                        "sec-websocket-accept",
                        RFC_SAMPLE_WEBSOCKET_ACCEPT,
                    )
                    && has_header(&headers.headers, "sec-websocket-protocol", SUBPROTOCOL)
        )
    })?;
    assert_has_event(envelopes, "WebSocket handoff", |envelope| {
        matches!(
            envelope.kind(),
            EventKind::WebSocketHandoff(handoff)
                if is_libpcap_event(envelope)
                    && handoff.direction == Direction::Inbound
                    && handoff.target.as_deref() == Some(REQUEST_TARGET)
                    && handoff.subprotocol.as_deref() == Some(SUBPROTOCOL)
        )
    })?;
    assert_has_event(envelopes, "WebSocket frame", |envelope| {
        matches!(
            envelope.kind(),
            EventKind::WebSocketFrame(frame)
                if is_libpcap_event(envelope)
                    && frame.direction == Direction::Inbound
                    && frame.frame_sequence == 1
                    && frame.fin
                    && !frame.masked
                    && matches!(frame.opcode, WebSocketOpcode::Text)
                    && frame.payload_len == FRAME_PAYLOAD_LEN
                    && frame.payload_fingerprint.as_slice()
                        == FRAME_PAYLOAD_FINGERPRINT.as_slice()
        )
    })?;
    assert_policy_alert(envelopes, HANDOFF_ALERT)?;
    assert_policy_alert(envelopes, FRAME_ALERT)?;
    assert_no_protocol_errors(envelopes)?;
    Ok(())
}

fn assert_has_event(
    envelopes: &[EventEnvelope],
    label: &str,
    predicate: impl Fn(&EventEnvelope) -> bool,
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes.iter().any(predicate) {
        return Ok(());
    }
    Err(e2e_error(format!("missing {CONTEXT} export event for {label}")).into())
}

fn assert_policy_alert(
    envelopes: &[EventEnvelope],
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter(|envelope| {
            is_libpcap_event(envelope)
                && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION)
                && matches!(envelope.kind(), EventKind::PolicyAlert(alert) if alert.message == message)
        })
        .count();
    if observed > 0 {
        return Ok(());
    }
    Err(e2e_error(format!("missing {CONTEXT} policy alert {message:?}")).into())
}

fn assert_no_protocol_errors(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes
        .iter()
        .any(|envelope| matches!(envelope.kind(), EventKind::ProtocolError(_)))
    {
        return Err(e2e_error(format!("{CONTEXT} produced a protocol error")).into());
    }
    Ok(())
}

fn is_libpcap_event(envelope: &EventEnvelope) -> bool {
    envelope.origin().source() == CaptureSource::Libpcap
        && envelope.origin().provider() == CaptureProviderKind::Libpcap
}
