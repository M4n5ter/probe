use std::{fs, path::Path, process::Command, process::ExitCode};

use capture::CaptureEvent;
use probe_core::{CaptureProviderKind, CaptureSource, Direction, EventEnvelope, EventKind};
use storage::FjallSpool;

use super::harness::{
    cargo_executable, decode_capture_event, decode_envelope, e2e_error, run_with_temp_root,
    workspace_root,
};

const AGENT_ID: &str = "e2e-replay-agent";
const POLICY_FILE_NAME: &str = "replay-policy.lua";
const REQUEST_TARGET: &str = "/e2e-replay";
const REQUEST_HOST: &str = "replay.e2e.test";
const EXPECTED_POLICY_VERSION: &str = "replay-policy@replay";
const EXPECTED_POLICY_ALERT: &str = "replay observed /e2e-replay";
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e";

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e replay failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("replay", run_at)?;
    println!("e2e replay passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let input_path = root.join("input.http");
    let policy_path = root.join(POLICY_FILE_NAME);
    let spool_path = root.join("spool");

    fs::write(&input_path, request_bytes())?;
    fs::write(&policy_path, policy_source())?;
    run_agent_replay(&input_path, &policy_path, &spool_path)?;
    assert_spool_outputs(&spool_path)?;

    Ok(())
}

fn run_agent_replay(
    input_path: &Path,
    policy_path: &Path,
    spool_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(cargo_executable())
        .current_dir(workspace_root()?)
        .args(["run", "-p", "agent", "--locked", "--", "replay", "--input"])
        .arg(input_path)
        .arg("--spool")
        .arg(spool_path)
        .arg("--policy")
        .arg(policy_path)
        .arg("--agent-id")
        .arg(AGENT_ID)
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    Err(e2e_error(format!(
        "agent replay exited with {}; stdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
    .into())
}

fn assert_spool_outputs(spool_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 16)?;
    let [ingress_event] = ingress.as_slice() else {
        return Err(e2e_error(format!(
            "expected one replay ingress record, got {}",
            ingress.len()
        ))
        .into());
    };
    assert_replay_ingress(&decode_capture_event(ingress_event)?)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 16)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    let [request, alert] = envelopes.as_slice() else {
        return Err(e2e_error(format!(
            "expected two replay export events, got {}",
            envelopes.len()
        ))
        .into());
    };
    assert_replay_request(request)?;
    assert_replay_policy_alert(alert)?;

    println!(
        "e2e replay observed {} ingress record and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn assert_replay_ingress(event: &CaptureEvent) -> Result<(), Box<dyn std::error::Error>> {
    if matches!(
        event,
        CaptureEvent::Bytes(bytes)
            if bytes.origin.source() == CaptureSource::Replay
                && bytes.origin.provider() == CaptureProviderKind::Replay
                && bytes.direction == Direction::Outbound
                && bytes.stream_offset == 0
                && bytes.bytes.as_ref() == request_bytes().as_slice()
    ) {
        return Ok(());
    }
    Err(e2e_error("missing expected replay ingress bytes event").into())
}

fn assert_replay_request(envelope: &EventEnvelope) -> Result<(), Box<dyn std::error::Error>> {
    if is_replay_event(envelope)
        && matches!(
            envelope.kind(),
            EventKind::HttpRequestHeaders(headers)
                if headers.method.as_deref() == Some("GET")
                    && headers.target.as_deref() == Some(REQUEST_TARGET)
        )
    {
        return Ok(());
    }
    Err(e2e_error("missing expected replay HTTP request headers export event").into())
}

fn assert_replay_policy_alert(envelope: &EventEnvelope) -> Result<(), Box<dyn std::error::Error>> {
    if is_replay_event(envelope)
        && envelope.policy_version() == Some(EXPECTED_POLICY_VERSION)
        && matches!(
            envelope.kind(),
            EventKind::PolicyAlert(alert) if alert.message == EXPECTED_POLICY_ALERT
        )
    {
        return Ok(());
    }
    Err(e2e_error("missing expected replay policy alert export event").into())
}

fn is_replay_event(envelope: &EventEnvelope) -> bool {
    envelope.origin().source() == CaptureSource::Replay
        && envelope.origin().provider() == CaptureProviderKind::Replay
}

fn request_bytes() -> Vec<u8> {
    format!("GET {REQUEST_TARGET} HTTP/1.1\r\nHost: {REQUEST_HOST}\r\n\r\n").into_bytes()
}

fn policy_source() -> &'static str {
    r#"function on_http_request_headers(event)
  return probe.emit_alert("replay observed " .. event.kind.target)
end
"#
}
