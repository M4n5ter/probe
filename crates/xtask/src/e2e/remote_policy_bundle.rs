use std::{fs, path::Path, process::ExitCode};

use probe_config::PolicySourceConfig;
use probe_core::{Direction, EventKind};
use storage::FjallSpool;

use super::harness::{
    HttpSourceServer, decode_envelope, e2e_error, run_agent_with_max_events, run_with_temp_root,
};
use super::plaintext_assertions::{
    assert_no_protocol_errors, assert_ordered_export_positions, assert_plaintext_feed_records,
    assert_policy_alert, export_event_position,
};
use super::plaintext_scenario::{
    PLAINTEXT_FEED_EVENT_COUNT, PlaintextFeedRecord, PlaintextFeedScenario, PlaintextFlow,
    PlaintextHttpRequest, PlaintextPolicy, PlaintextProcess, PlaintextScenarioIds,
};

const E2E_EXPORT_CURSOR_OWNER: &str = "e2e";
const AGENT_ID: &str = "e2e-remote-policy-agent";
const CONFIG_VERSION: &str = "e2e-remote-policy-bundle";
const CONNECTION_ID: &str = "xtask-e2e-remote-policy-conn";
const POLICY_ID: &str = "e2e-remote-policy";
const POLICY_VERSION: &str = "remote";
const REQUEST_TARGET: &str = "/remote-policy/e2e";
const BUNDLE_REQUEST_TARGET: &str = "/policies/e2e-remote-policy";
const ALERT_PREFIX: &str = "remote policy bundle observed ";
const CONTEXT: &str = "remote policy bundle";

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e remote policy bundle failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("remote-policy-bundle", run_at)?;
    println!("e2e remote policy bundle passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("feed.jsonl");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let scenario = scenario();
    scenario.write_feed(&feed_path)?;
    let bundle_server =
        HttpSourceServer::spawn(BUNDLE_REQUEST_TARGET, "application/toml", bundle_document())?;
    let mut config = scenario.agent_config_with_policy_source(
        feed_path,
        PolicySourceConfig::RemoteBundle {
            endpoint: bundle_server.endpoint(),
            max_body_bytes: Some(1024 * 1024),
        },
        spool_path.clone(),
    );
    config.export.worker.enabled = false;
    fs::write(&config_path, toml::to_string(&config)?)?;

    run_agent_with_max_events(&config_path, PLAINTEXT_FEED_EVENT_COUNT)?;
    let bundle_requests = bundle_server.finish()?;
    if bundle_requests != 1 {
        return Err(e2e_error(format!(
            "expected exactly one remote policy bundle request, got {bundle_requests}"
        ))
        .into());
    }
    assert_spool_outputs(&spool_path, &scenario)?;

    Ok(())
}

fn scenario() -> PlaintextFeedScenario {
    PlaintextFeedScenario::new(
        PlaintextScenarioIds::new(
            AGENT_ID,
            CONFIG_VERSION,
            POLICY_ID,
            POLICY_VERSION,
            CONNECTION_ID,
        ),
        PlaintextHttpRequest::get(REQUEST_TARGET, "remote-policy.e2e.test"),
        PlaintextPolicy::alerting(ALERT_PREFIX),
    )
    .with_flow(PlaintextFlow::new(
        52_300,
        8_082,
        2_201,
        PlaintextProcess::new(
            620,
            1_120,
            "traffic-probe-e2e-remote-policy",
            "/usr/bin/traffic-probe-e2e-remote-policy",
            "remote-policy-hash",
        ),
    ))
}

fn bundle_document() -> String {
    format!(
        r#"source = '''
function on_http_request_headers(event)
  return probe.emit_alert("{ALERT_PREFIX}" .. event.kind.target)
end
'''

[manifest]
id = "{POLICY_ID}"
version = "{POLICY_VERSION}"
hooks = ["on_http_request_headers"]
"#
    )
}

fn assert_spool_outputs(
    spool_path: &Path,
    scenario: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let ingress = spool.read_ingress_batch_after(0, 16)?;
    assert_plaintext_feed_records(
        &ingress,
        scenario.feed_case(),
        &[
            PlaintextFeedRecord::connection_opened(),
            PlaintextFeedRecord::bytes(Direction::Outbound, 0, scenario.request_bytes()),
            PlaintextFeedRecord::connection_closed(),
        ],
        CONTEXT,
    )?;

    let envelopes = spool
        .read_export_batch(E2E_EXPORT_CURSOR_OWNER, 64)?
        .iter()
        .map(decode_envelope)
        .collect::<Result<Vec<_>, _>>()?;
    let opened = export_event_position(
        &envelopes,
        scenario.feed_case(),
        CONTEXT,
        "connection opened",
        |kind| matches!(kind, EventKind::ConnectionOpened),
    )?;
    let request = export_event_position(
        &envelopes,
        scenario.feed_case(),
        CONTEXT,
        "HTTP request headers",
        |kind| {
            matches!(
                kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.direction == Direction::Outbound
                        && headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(scenario.request_target())
            )
        },
    )?;
    let alert = export_event_position(
        &envelopes,
        scenario.feed_case(),
        CONTEXT,
        "policy alert",
        |kind| {
            matches!(
                kind,
                EventKind::PolicyAlert(alert)
                    if alert.message == scenario.expected_policy_alert_message()
            )
        },
    )?;
    let closed = export_event_position(
        &envelopes,
        scenario.feed_case(),
        CONTEXT,
        "connection closed",
        |kind| matches!(kind, EventKind::ConnectionClosed),
    )?;
    assert_ordered_export_positions(
        CONTEXT,
        &[
            ("opened", opened),
            ("request", request),
            ("alert", alert),
            ("closed", closed),
        ],
    )?;
    assert_policy_alert(
        &envelopes,
        scenario.feed_case(),
        &scenario.expected_policy_version(),
        CONTEXT,
        &scenario.expected_policy_alert_message(),
    )?;
    assert_no_protocol_errors(&envelopes, CONTEXT)?;
    assert_no_policy_runtime_errors(&envelopes)?;

    println!(
        "e2e remote policy bundle observed {} ingress records and {} export records",
        ingress.len(),
        envelopes.len()
    );
    Ok(())
}

fn assert_no_policy_runtime_errors(
    envelopes: &[probe_core::EventEnvelope],
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes
        .iter()
        .any(|envelope| matches!(envelope.kind(), EventKind::PolicyRuntimeError(_)))
    {
        return Err(e2e_error("remote policy bundle produced a policy runtime error").into());
    }
    Ok(())
}
