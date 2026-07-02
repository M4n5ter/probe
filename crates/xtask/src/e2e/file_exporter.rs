use std::{fs, path::Path, process::ExitCode};

use exporter::CompressionCodec;
use probe_config::{ExporterConfig, ExporterTransportConfig};

use super::harness::{run_agent_with_max_events, run_with_temp_root};
use super::plaintext_export_batches::{
    assert_batch_sequence_contract, assert_expected_export_set, assert_export_cursor,
    assert_file_export_batch_records, compression_codec_name, decode_and_assert_event_records,
};
use super::plaintext_scenario::{
    PLAINTEXT_FEED_EVENT_COUNT, PlaintextFeedScenario, PlaintextFlow, PlaintextHttpRequest,
    PlaintextPolicy, PlaintextProcess, PlaintextScenarioIds,
};

const FILE_SINK: &str = "local-file";
const AGENT_ID: &str = "e2e-file-export-agent";
const POLICY_ID: &str = "e2e-file-export-policy";
const POLICY_VERSION: &str = "e2e";
const REQUEST_TARGET: &str = "/e2e-file-export";
const TEST_CODEC: CompressionCodec = CompressionCodec::Zstd;

pub(crate) fn run() -> ExitCode {
    match run_inner() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("e2e file exporter failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn run_inner() -> Result<(), Box<dyn std::error::Error>> {
    run_with_temp_root("file-exporter", run_at)?;
    println!("e2e file exporter passed");
    Ok(())
}

fn run_at(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all(root)?;
    let feed_path = root.join("feed.jsonl");
    let policy_path = root.join("e2e-file-export-policy.bundle");
    let config_path = root.join("agent.toml");
    let spool_path = root.join("spool");
    let export_path = root.join("export.jsonl");

    let scenario = scenario();
    scenario.write_feed(&feed_path)?;
    scenario.write_policy_bundle(&policy_path)?;
    write_agent_config(
        &scenario,
        &config_path,
        feed_path,
        policy_path,
        spool_path.clone(),
        export_path.clone(),
    )?;
    run_agent_with_max_events(&config_path, PLAINTEXT_FEED_EVENT_COUNT)?;
    let expected_cursor = assert_file_export(&export_path, &scenario)?;
    assert_export_cursor(&spool_path, FILE_SINK, expected_cursor)?;

    Ok(())
}

fn scenario() -> PlaintextFeedScenario {
    PlaintextFeedScenario::new(
        PlaintextScenarioIds::new(
            AGENT_ID,
            "e2e-file-exporter",
            POLICY_ID,
            POLICY_VERSION,
            "xtask-e2e-file-export-conn",
        ),
        PlaintextHttpRequest::get(REQUEST_TARGET, "file-export.e2e.test"),
        PlaintextPolicy::alerting("file exporter observed "),
    )
    .with_flow(PlaintextFlow::new(
        51_100,
        8_081,
        1002,
        PlaintextProcess::new(
            322,
            655,
            "traffic-probe-e2e-file-export",
            "/usr/bin/traffic-probe-e2e-file-export",
            "file-export-hash",
        ),
    ))
}

fn write_agent_config(
    scenario: &PlaintextFeedScenario,
    path: &Path,
    feed_path: std::path::PathBuf,
    policy_path: std::path::PathBuf,
    spool_path: std::path::PathBuf,
    export_path: std::path::PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut config = scenario.agent_config(feed_path, policy_path, spool_path);
    config.export.worker.enabled = false;
    config.exporters.push(ExporterConfig {
        id: FILE_SINK.to_string(),
        transport: ExporterTransportConfig::File { path: export_path },
        codec: compression_codec_name(TEST_CODEC),
        worker: Default::default(),
    });
    fs::write(path, toml::to_string(&config)?)?;
    Ok(())
}

fn assert_file_export(
    path: &Path,
    scenario: &PlaintextFeedScenario,
) -> Result<u64, Box<dyn std::error::Error>> {
    let (records, batches) =
        assert_file_export_batch_records(path, AGENT_ID, FILE_SINK, TEST_CODEC, "file exporter")?;
    let expected_cursor =
        assert_batch_sequence_contract(&batches, AGENT_ID, FILE_SINK, "file exporter records")?;
    let envelopes = decode_and_assert_event_records(&batches, "file exporter records")?;
    assert_expected_export_set(&envelopes, scenario, "file exporter records")?;

    println!(
        "e2e file exporter observed {} JSON Lines records carrying {} exported events",
        records.len(),
        envelopes.len()
    );
    Ok(expected_cursor)
}
