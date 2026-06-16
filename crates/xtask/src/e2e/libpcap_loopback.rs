use std::{collections::BTreeSet, fs, path::Path, process::ExitCode};

use capture::CaptureEvent;
use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};
use probe_core::{CaptureSource, Direction, EventEnvelope, EventKind};
use storage::{FjallSpool, StoredEvent};

use super::{
    harness::{
        ChildSupervisor, UnixSocketReadySignal, create_temp_root, decode_capture_event,
        decode_envelope, e2e_error, ensure_e2e_packages_built, stop_running_child,
    },
    loopback::{
        Http1LoopbackFixtureConfig, assert_no_policy_runtime_errors, merge_run_results,
        spawn_agent, spawn_http1_loopback_fixture, start_http1_loopback_fixture,
        wait_for_agent_policy_progress, wait_for_agent_ready, wait_for_http1_loopback_fixture_exit,
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
        (Ok(()), Ok(())) => assert_spool_outputs(&spool_path),
        _ => Ok(()),
    };
    merge_run_results(fixture_result, progress_result, agent_result, spool_result)?;

    Ok(())
}

fn fixture_config() -> Http1LoopbackFixtureConfig {
    Http1LoopbackFixtureConfig {
        listen_port: None,
        requests: REQUESTS,
        request_body_bytes: REQUEST_BODY_BYTES,
        response_body_bytes: RESPONSE_BODY_BYTES,
        write_chunks: WRITE_CHUNKS,
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
hooks = ["on_http_request_headers"]
"#
        ),
    )?;
    fs::write(
        path.join("main.lua"),
        r#"
function on_http_request_headers(event)
  local target = event.kind.target or ""
  if string.sub(target, 1, 10) == "/sssa-e2e/" then
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
        path: policy_path.to_path_buf(),
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
        return Err(e2e_error("expected libpcap ingress records, got none").into());
    }
    assert_libpcap_ingress(&ingress)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 512)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    assert_no_policy_runtime_errors(&envelopes)?;
    assert_expected_requests(&envelopes)?;
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
                    if bytes.source == CaptureSource::Libpcap
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

fn assert_expected_requests(envelopes: &[EventEnvelope]) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match &envelope.kind {
            EventKind::HttpRequestHeaders(headers)
                if envelope.source == CaptureSource::Libpcap
                    && headers.direction == Direction::Outbound
                    && headers.method.as_deref() == Some("POST") =>
            {
                headers.target.clone()
            }
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    let expected = expected_targets();
    if observed.is_superset(&expected) {
        return Ok(());
    }

    Err(e2e_error(format!(
        "missing libpcap HTTP request targets; expected at least {:?}, observed {:?}",
        expected, observed
    ))
    .into())
}

fn assert_expected_policy_alerts(
    envelopes: &[EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    let observed = envelopes
        .iter()
        .filter_map(|envelope| match &envelope.kind {
            EventKind::PolicyAlert(alert)
                if envelope.source == CaptureSource::Libpcap
                    && envelope.policy_version.as_deref() == Some(EXPECTED_POLICY_VERSION) =>
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
        .map(|request| format!("/sssa-e2e/{request}"))
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
