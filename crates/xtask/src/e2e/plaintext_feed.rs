use std::{fs, path::Path, process::ExitCode};

use capture::CaptureEvent;
use probe_core::{CaptureSource, EventEnvelope, EventKind};
use storage::{FjallSpool, StoredEvent};

use super::harness::{
    decode_capture_event, decode_envelope, e2e_error, run_agent_with_max_events, run_with_temp_root,
};
use super::plaintext_scenario::{
    PLAINTEXT_FEED_EVENT_COUNT, PlaintextFeedScenario, PlaintextHttpRequest, PlaintextPolicy,
    PlaintextScenarioIds,
};

const CONNECTION_ID: &str = "xtask-e2e-conn";
const E2E_EXPORT_CURSOR_OWNER: &str = "e2e";
const POLICY_ID: &str = "e2e-policy";
const POLICY_VERSION: &str = "e2e";
const REQUEST_TARGET: &str = "/e2e";

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
    run_with_temp_root("plaintext-feed", run_at)?;
    println!("e2e plaintext feed passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("feed.jsonl");
    let policy_path = root.join("e2e-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let scenario = scenario();
    scenario.write_feed(&feed_path)?;
    scenario.write_policy_bundle(&policy_path)?;
    let mut config = scenario.agent_config(feed_path, policy_path, spool_path.clone());
    config.export.worker.enabled = false;
    fs::write(&config_path, toml::to_string(&config)?)?;
    run_agent_with_max_events(&config_path, PLAINTEXT_FEED_EVENT_COUNT)?;
    assert_spool_outputs(&spool_path, &scenario)?;

    Ok(())
}

fn scenario() -> PlaintextFeedScenario {
    PlaintextFeedScenario::new(
        PlaintextScenarioIds::new(
            "e2e-agent",
            "e2e-plaintext-feed",
            POLICY_ID,
            POLICY_VERSION,
            CONNECTION_ID,
        ),
        PlaintextHttpRequest::get(REQUEST_TARGET, "e2e.test"),
        PlaintextPolicy::alerting("e2e policy observed "),
    )
}

fn assert_spool_outputs(
    spool_path: &Path,
    scenario: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 16)?;
    if ingress.len() != PLAINTEXT_FEED_EVENT_COUNT {
        return Err(e2e_error(format!(
            "expected {PLAINTEXT_FEED_EVENT_COUNT} ingress records, got {}",
            ingress.len()
        ))
        .into());
    }
    assert_ingress_events(&ingress, scenario)?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 64)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    let request_found = envelopes.iter().any(|envelope| {
        is_expected_feed_flow(envelope, scenario)
            && matches!(
                &envelope.kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(scenario.request_target())
            )
    });
    if !request_found {
        return Err(e2e_error("missing parsed HTTP request headers for /e2e").into());
    }

    let expected_policy_version = scenario.expected_policy_version();
    let expected_alert = scenario.expected_policy_alert_message();
    let policy_alert_found = envelopes.iter().any(|envelope| {
        is_expected_feed_flow(envelope, scenario)
            && envelope.policy_version.as_deref() == Some(expected_policy_version.as_str())
            && matches!(
                &envelope.kind,
                EventKind::PolicyAlert(alert)
                    if alert.message == expected_alert
            )
    });
    if !policy_alert_found {
        return Err(e2e_error("missing configured policy alert for /e2e").into());
    }

    let lifecycle_found = envelopes.iter().any(|envelope| {
        is_expected_feed_flow(envelope, scenario)
            && matches!(envelope.kind, EventKind::ConnectionOpened)
    }) && envelopes.iter().any(|envelope| {
        is_expected_feed_flow(envelope, scenario)
            && matches!(envelope.kind, EventKind::ConnectionClosed)
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

fn assert_ingress_events(
    events: &[StoredEvent],
    scenario: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let capture_events = events
        .iter()
        .map(decode_capture_event)
        .collect::<Result<Vec<_>, _>>()?;
    let [opened, bytes, closed] = capture_events.as_slice() else {
        return Err(e2e_error(format!(
            "expected {PLAINTEXT_FEED_EVENT_COUNT} ordered ingress events, got {}",
            capture_events.len()
        ))
        .into());
    };

    if !matches!(
        opened,
        CaptureEvent::ConnectionOpened { source, flow, .. }
            if *source == CaptureSource::ExternalPlaintextFeed
                && flow.id.0 == scenario.expected_flow_id()
    ) {
        return Err(e2e_error("missing expected ingress connection_opened event").into());
    }
    if !matches!(
        bytes,
        CaptureEvent::Bytes(bytes)
            if bytes.source == CaptureSource::ExternalPlaintextFeed
                && bytes.flow.id.0 == scenario.expected_flow_id()
                && bytes.bytes.as_ref() == scenario.request_bytes().as_slice()
    ) {
        return Err(e2e_error("missing expected ingress bytes event").into());
    }
    if !matches!(
        closed,
        CaptureEvent::ConnectionClosed { source, flow, .. }
            if *source == CaptureSource::ExternalPlaintextFeed
                && flow.id.0 == scenario.expected_flow_id()
    ) {
        return Err(e2e_error("missing expected ingress connection_closed event").into());
    }
    Ok(())
}

fn is_expected_feed_flow(envelope: &EventEnvelope, scenario: &PlaintextFeedScenario) -> bool {
    envelope.source == CaptureSource::ExternalPlaintextFeed
        && envelope.flow.id.0 == scenario.expected_flow_id()
}
