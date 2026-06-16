use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::{Command, ExitCode},
    time::{SystemTime, UNIX_EPOCH},
};

use capture::CaptureEvent;
use probe_config::{AgentConfig, CaptureSelection, PolicyConfig};
use probe_core::{CaptureSource, EventEnvelope, EventKind, SpoolPayloadSchema};
use storage::{FjallSpool, StoredEvent};

const CONNECTION_ID: &str = "xtask-e2e-conn";
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e";
const EXPECTED_FLOW_ID: &str = "external_plaintext_feed:xtask-e2e-conn";
const EXPECTED_INGRESS_EVENTS: usize = 3;
const POLICY_ID: &str = "e2e-policy";
const POLICY_VERSION: &str = "e2e";
const EXPECTED_POLICY_VERSION: &str = "e2e-policy@e2e";
const REQUEST_TARGET: &str = "/e2e";
const REQUEST_BYTES: &[u8] = b"GET /e2e HTTP/1.1\r\nHost: e2e.test\r\n\r\n";
const POLICY_ALERT_MESSAGE: &str = "e2e policy observed /e2e";

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e plaintext feed failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    let root = create_temp_root("plaintext-feed")?;
    match run_at(&root) {
        Ok(()) => {
            fs::remove_dir_all(&root)?;
            println!("e2e plaintext feed passed");
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
    let feed_path = root.join("feed.jsonl");
    let policy_path = root.join("e2e-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    write_plaintext_feed(&feed_path)?;
    write_policy_bundle(&policy_path)?;
    write_agent_config(&config_path, &feed_path, &policy_path, &spool_path)?;
    run_agent(&config_path)?;
    assert_spool_outputs(&spool_path)?;

    Ok(())
}

fn create_temp_root(name: &str) -> Result<PathBuf, std::io::Error> {
    let path = env::temp_dir().join(format!(
        "sssa-probe-e2e-{name}-{}-{}",
        std::process::id(),
        wall_time_unix_ns()
    ));
    if path.exists() {
        fs::remove_dir_all(&path)?;
    }
    fs::create_dir_all(&path)?;
    Ok(path)
}

fn write_plaintext_feed(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let connection = feed_connection();
    let records = [
        serde_json::json!({
            "type": "connection_opened",
            "timestamp": feed_timestamp(1),
            "connection": connection.clone(),
        }),
        serde_json::json!({
            "type": "bytes",
            "timestamp": feed_timestamp(2),
            "connection": connection.clone(),
            "direction": "outbound",
            "stream_offset": 0,
            "bytes": REQUEST_BYTES,
        }),
        serde_json::json!({
            "type": "connection_closed",
            "timestamp": feed_timestamp(3),
            "connection": connection,
        }),
    ];
    let mut content = String::new();
    for record in records {
        content.push_str(&serde_json::to_string(&record)?);
        content.push('\n');
    }
    fs::write(path, content)?;
    Ok(())
}

fn feed_connection() -> serde_json::Value {
    serde_json::json!({
        "connection_id": CONNECTION_ID,
        "local": {
            "address": "127.0.0.1",
            "port": 50000,
        },
        "remote": {
            "address": "127.0.0.1",
            "port": 80,
        },
        "protocol": "tcp",
        "start_monotonic_ns": 1,
        "socket_cookie": 99,
        "attribution_confidence": 100,
        "process": {
            "pid": 123,
            "tgid": 123,
            "start_time_ticks": 456,
            "boot_id": "boot",
            "exe_path": "/usr/bin/sssa-e2e",
            "cmdline_hash": "hash",
            "uid": 1000,
            "gid": 1000,
            "name": "sssa-e2e",
            "cmdline": ["sssa-e2e"],
        },
    })
}

fn feed_timestamp(monotonic_ns: u64) -> serde_json::Value {
    serde_json::json!({
        "monotonic_ns": monotonic_ns,
        "wall_time_unix_ns": i64::try_from(monotonic_ns).unwrap_or(i64::MAX),
    })
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
  return probe.emit_alert("e2e policy observed " .. event.kind.target)
end
"#,
    )
}

fn write_agent_config(
    path: &Path,
    feed_path: &Path,
    policy_path: &Path,
    spool_path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = AgentConfig {
        agent_id: "e2e-agent".to_string(),
        config_version: "e2e-plaintext-feed".to_string(),
        ..AgentConfig::default()
    };
    config.capture.selection = CaptureSelection::PlaintextFeed;
    config.capture.plaintext_feed.path = Some(feed_path.to_path_buf());
    config.storage.path = spool_path.to_path_buf();
    config.export.worker.enabled = false;
    config.policies.push(PolicyConfig {
        id: POLICY_ID.to_string(),
        path: policy_path.to_path_buf(),
        enabled: true,
        selector: None,
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn run_agent(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let max_events = EXPECTED_INGRESS_EVENTS.to_string();
    let status = Command::new(cargo_executable())
        .current_dir(workspace_root()?)
        .args(["run", "-p", "agent", "--locked", "--", "run", "--config"])
        .arg(config_path)
        .args(["--max-events", &max_events])
        .status()?;
    if status.success() {
        return Ok(());
    }

    Err(e2e_error(format!("agent run exited with {status}")).into())
}

fn assert_spool_outputs(spool_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 16)?;
    if ingress.len() != EXPECTED_INGRESS_EVENTS {
        return Err(e2e_error(format!(
            "expected {EXPECTED_INGRESS_EVENTS} ingress records, got {}",
            ingress.len()
        ))
        .into());
    }
    assert_ingress_events(&ingress)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 64)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    let request_found = envelopes.iter().any(|envelope| {
        is_expected_feed_flow(envelope)
            && matches!(
                &envelope.kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(REQUEST_TARGET)
            )
    });
    if !request_found {
        return Err(e2e_error("missing parsed HTTP request headers for /e2e").into());
    }

    let policy_alert_found = envelopes.iter().any(|envelope| {
        is_expected_feed_flow(envelope)
            && envelope.policy_version.as_deref() == Some(EXPECTED_POLICY_VERSION)
            && matches!(
                &envelope.kind,
                EventKind::PolicyAlert(alert)
                    if alert.message == POLICY_ALERT_MESSAGE
            )
    });
    if !policy_alert_found {
        return Err(e2e_error("missing configured policy alert for /e2e").into());
    }

    let lifecycle_found = envelopes.iter().any(|envelope| {
        is_expected_feed_flow(envelope) && matches!(envelope.kind, EventKind::ConnectionOpened)
    }) && envelopes.iter().any(|envelope| {
        is_expected_feed_flow(envelope) && matches!(envelope.kind, EventKind::ConnectionClosed)
    });
    if !lifecycle_found {
        return Err(e2e_error("missing connection lifecycle events").into());
    }

    println!(
        "e2e plaintext feed observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn assert_ingress_events(events: &[StoredEvent]) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    let [opened, bytes, closed] = capture_events.as_slice() else {
        return Err(e2e_error(format!(
            "expected {EXPECTED_INGRESS_EVENTS} ordered ingress events, got {}",
            capture_events.len()
        ))
        .into());
    };

    if !matches!(
        opened,
        CaptureEvent::ConnectionOpened { source, flow, .. }
            if *source == CaptureSource::ExternalPlaintextFeed && flow.id.0 == EXPECTED_FLOW_ID
    ) {
        return Err(e2e_error("missing expected ingress connection_opened event").into());
    }
    if !matches!(
        bytes,
        CaptureEvent::Bytes(bytes)
            if bytes.source == CaptureSource::ExternalPlaintextFeed
                && bytes.flow.id.0 == EXPECTED_FLOW_ID
                && bytes.bytes.as_ref() == REQUEST_BYTES
    ) {
        return Err(e2e_error("missing expected ingress bytes event").into());
    }
    if !matches!(
        closed,
        CaptureEvent::ConnectionClosed { source, flow, .. }
            if *source == CaptureSource::ExternalPlaintextFeed && flow.id.0 == EXPECTED_FLOW_ID
    ) {
        return Err(e2e_error("missing expected ingress connection_closed event").into());
    }
    Ok(())
}

fn is_expected_feed_flow(envelope: &EventEnvelope) -> bool {
    envelope.source == CaptureSource::ExternalPlaintextFeed
        && envelope.flow.id.0 == EXPECTED_FLOW_ID
}

fn decode_capture_event(event: &StoredEvent) -> Result<CaptureEvent, Box<dyn std::error::Error>> {
    if event.payload.schema() != &SpoolPayloadSchema::CaptureEventJson {
        return Err(e2e_error(format!(
            "ingress record {} used unexpected schema {}",
            event.sequence,
            event.payload.schema_wire()
        ))
        .into());
    }
    serde_json::from_slice::<CaptureEvent>(event.payload.bytes()).map_err(Into::into)
}

fn decode_envelope(event: &StoredEvent) -> Result<EventEnvelope, Box<dyn std::error::Error>> {
    if event.payload.schema() != &SpoolPayloadSchema::EventEnvelopeJson {
        return Err(e2e_error(format!(
            "export record {} used unexpected schema {}",
            event.sequence,
            event.payload.schema_wire()
        ))
        .into());
    }
    serde_json::from_slice::<EventEnvelope>(event.payload.bytes()).map_err(Into::into)
}

fn cargo_executable() -> OsString {
    env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"))
}

fn workspace_root() -> Result<PathBuf, std::io::Error> {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|crates_dir| crates_dir.parent())
        .map(Path::to_path_buf)
        .ok_or_else(|| e2e_error("failed to resolve workspace root"))
}

fn wall_time_unix_ns() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| {
            i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX)
        })
}

fn e2e_error(message: impl Into<String>) -> std::io::Error {
    std::io::Error::other(message.into())
}
