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
use super::webhook_receiver::{ReceivedBatch, UnixHttpBatchReceiver};

const COLLECTOR_SINK: &str = "local-sidecar";
const AGENT_ID: &str = "e2e-unix-http-export-agent";
const POLICY_ID: &str = "e2e-unix-http-export-policy";
const POLICY_VERSION: &str = "e2e";
const REQUEST_TARGET: &str = "/e2e-unix-http-export";
const EXPORT_ENDPOINT: &str = "/probe/batches?tenant=local";
const TEST_CODEC: CompressionCodec = CompressionCodec::Deflate;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e unix_http exporter failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("unix-http-exporter", run_at)?;
    println!("e2e unix_http exporter passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("feed.jsonl");
    let policy_path = root.join("e2e-unix-http-export-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let socket_path = root.join("collector.sock");
    let receiver = UnixHttpBatchReceiver::spawn(socket_path.clone(), EXPORT_ENDPOINT)?;

    let scenario = scenario();
    scenario.write_feed(&feed_path)?;
    scenario.write_policy_bundle(&policy_path)?;
    write_agent_config(
        &scenario,
        &config_path,
        feed_path,
        policy_path,
        spool_path.clone(),
        receiver.socket_path(),
    )?;
    run_agent_with_max_events(&config_path, PLAINTEXT_FEED_EVENT_COUNT)?;
    let batches = receiver.join()?;
    let expected_cursor = assert_unix_http_batches(&batches, &scenario)?;
    assert_export_cursor(&spool_path, COLLECTOR_SINK, expected_cursor)?;

    Ok(())
}

fn scenario() -> PlaintextFeedScenario {
    PlaintextFeedScenario::new(
        PlaintextScenarioIds::new(
            AGENT_ID,
            "e2e-unix-http-exporter",
            POLICY_ID,
            POLICY_VERSION,
            "xtask-e2e-unix-http-export-conn",
        ),
        PlaintextHttpRequest::get(REQUEST_TARGET, "unix-http-export.e2e.test"),
        PlaintextPolicy::alerting("unix_http exporter observed "),
    )
    .with_flow(PlaintextFlow::new(
        51_200,
        8_082,
        1003,
        PlaintextProcess::new(
            323,
            656,
            "traffic-probe-e2e-unix-http-export",
            "/usr/bin/traffic-probe-e2e-unix-http-export",
            "unix-http-export-hash",
        ),
    ))
}

fn write_agent_config(
    scenario: &PlaintextFeedScenario,
    path: &Path,
    feed_path: std::path::PathBuf,
    policy_path: std::path::PathBuf,
    spool_path: std::path::PathBuf,
    socket_path: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = scenario.agent_config(feed_path, policy_path, spool_path);
    config.export.worker.enabled = false;
    config.exporters.push(ExporterConfig {
        id: COLLECTOR_SINK.to_string(),
        transport: ExporterTransportConfig::UnixHttp {
            socket_path,
            endpoint: EXPORT_ENDPOINT.to_string(),
            headers: BTreeMap::from([(
                "x-traffic-probe-e2e".to_string(),
                "unix-http-exporter".to_string(),
            )]),
        },
        codec: compression_codec_name(TEST_CODEC),
        worker: Default::default(),
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_unix_http_batches(
    batches: &[ReceivedBatch],
    scenario: &PlaintextFeedScenario,
) -> Result<u64, Box<dyn std::error::Error>> {
    if batches.is_empty() {
        return Err(e2e_error("unix_http receiver captured no batches").into());
    }
    if !batches.iter().all(|batch| batch.codec == TEST_CODEC) {
        return Err(e2e_error("unix_http receiver observed an unexpected codec").into());
    }
    if !batches.iter().all(|batch| {
        batch
            .headers
            .get("x-traffic-probe-e2e")
            .is_some_and(|value| value == "unix-http-exporter")
    }) {
        return Err(e2e_error("unix_http receiver did not observe configured header").into());
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
        "unix_http batches",
    )?;
    let envelopes = decode_and_assert_event_records(&batch_envelopes, "unix_http batches")?;
    assert_expected_export_set(&envelopes, scenario, "unix_http batches")?;

    println!(
        "e2e unix_http exporter observed {} Unix socket HTTP requests carrying {} exported events",
        batches.len(),
        envelopes.len()
    );
    Ok(expected_cursor)
}
