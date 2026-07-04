use std::{collections::BTreeMap, fs, path::Path, process::ExitCode};

use exporter::CompressionCodec;
use probe_config::{ExporterConfig, ExporterTransportConfig};

use super::harness::{e2e_error, run_agent_with_max_events, run_with_temp_root};
use super::plaintext_export_batches::{
    assert_batch_sequence_contract, assert_expected_export_set, assert_export_cursor,
    compression_codec_name, decode_and_assert_event_records,
};
use super::plaintext_scenario::{
    PLAINTEXT_FEED_EVENT_COUNT, PLAINTEXT_FEED_EXPORT_EVENT_COUNT, PlaintextFeedScenario,
    PlaintextFlow, PlaintextHttpRequest, PlaintextPolicy, PlaintextProcess, PlaintextScenarioIds,
};
use super::webhook_receiver::{ReceivedBatch, WebhookBatchReceiver};

const COLLECTOR_SINK: &str = "collector";
const AGENT_ID: &str = "e2e-export-agent";
const POLICY_ID: &str = "e2e-export-policy";
const POLICY_VERSION: &str = "e2e";
const REQUEST_TARGET: &str = "/e2e-export";
const TEST_CODEC: CompressionCodec = CompressionCodec::Gzip;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e webhook exporter failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("webhook-exporter", run_at)?;
    println!("e2e webhook exporter passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let receiver = WebhookBatchReceiver::spawn()?;
    let feed_path = root.join("feed.jsonl");
    let policy_path = root.join("e2e-export-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");

    let scenario = scenario();
    scenario.write_feed(&feed_path)?;
    scenario.write_policy_bundle(&policy_path)?;
    write_agent_config(
        &scenario,
        &config_path,
        feed_path,
        policy_path,
        spool_path.clone(),
        receiver.endpoint(),
    )?;
    run_agent_with_max_events(&config_path, PLAINTEXT_FEED_EVENT_COUNT)?;
    let batches = receiver.join()?;
    let expected_cursor = assert_webhook_batches(&batches, &scenario)?;
    assert_export_cursor(&spool_path, COLLECTOR_SINK, expected_cursor)?;

    Ok(())
}

fn scenario() -> PlaintextFeedScenario {
    PlaintextFeedScenario::new(
        PlaintextScenarioIds::new(
            AGENT_ID,
            "e2e-webhook-exporter",
            POLICY_ID,
            POLICY_VERSION,
            "xtask-e2e-export-conn",
        ),
        PlaintextHttpRequest::get(REQUEST_TARGET, "export.e2e.test"),
        PlaintextPolicy::alerting("webhook exporter observed "),
    )
    .with_flow(PlaintextFlow::new(
        51_000,
        8_080,
        1001,
        PlaintextProcess::new(
            321,
            654,
            "traffic-probe-e2e-export",
            "/usr/bin/traffic-probe-e2e-export",
            "export-hash",
        ),
    ))
}

fn write_agent_config(
    scenario: &PlaintextFeedScenario,
    path: &Path,
    feed_path: std::path::PathBuf,
    policy_path: std::path::PathBuf,
    spool_path: std::path::PathBuf,
    endpoint: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = scenario.agent_config(feed_path, policy_path, spool_path);
    config.export.worker.enabled = false;
    config.exporters.push(ExporterConfig {
        id: COLLECTOR_SINK.to_string(),
        transport: ExporterTransportConfig::Webhook {
            endpoint,
            headers: BTreeMap::from([(
                "x-traffic-probe-e2e".to_string(),
                "webhook-exporter".to_string(),
            )]),
            tls: Default::default(),
        },
        codec: compression_codec_name(TEST_CODEC),
        worker: Default::default(),
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_webhook_batches(
    batches: &[ReceivedBatch],
    scenario: &PlaintextFeedScenario,
) -> Result<u64, Box<dyn std::error::Error>> {
    if batches.is_empty() {
        return Err(e2e_error("webhook receiver captured no batches").into());
    }
    if !batches.iter().all(|batch| batch.codec == TEST_CODEC) {
        return Err(e2e_error("webhook receiver observed an unexpected codec").into());
    }
    if !batches.iter().all(|batch| {
        batch
            .headers
            .get("x-traffic-probe-e2e")
            .is_some_and(|value| value == "webhook-exporter")
    }) {
        return Err(e2e_error("webhook receiver did not observe configured header").into());
    }

    let batch_envelopes = batches
        .iter()
        .map(|batch| batch.batch.clone())
        .collect::<Vec<_>>();
    let expected_cursor = assert_batch_sequence_contract(
        &batch_envelopes,
        AGENT_ID,
        COLLECTOR_SINK,
        PLAINTEXT_FEED_EXPORT_EVENT_COUNT,
        "webhook batches",
    )?;
    let envelopes = decode_and_assert_event_records(&batch_envelopes, "webhook batches")?;
    assert_expected_export_set(&envelopes, scenario, "webhook batches")?;

    println!(
        "e2e webhook exporter observed {} HTTP requests carrying {} exported events",
        batches.len(),
        envelopes.len()
    );
    Ok(expected_cursor)
}
