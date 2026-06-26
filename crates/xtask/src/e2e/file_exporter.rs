use std::{fs, os::unix::fs::PermissionsExt, path::Path, process::ExitCode};

use exporter::{CompressionCodec, FileBatchRecord, FileBatchRecordKind};
use probe_config::{ExporterConfig, ExporterTransportConfig};
use proto::BatchEnvelope;

use super::harness::{e2e_error, run_agent_with_max_events, run_with_temp_root};
use super::plaintext_export_batches::{
    assert_batch_sequence_contract, assert_expected_export_set, assert_export_cursor,
    compression_codec_name, decode_and_assert_event_records, expected_batch_id,
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
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(e2e_error(format!(
            "file exporter created {} as a symlink",
            path.display()
        ))
        .into());
    }
    if !metadata.file_type().is_file() {
        return Err(e2e_error(format!(
            "file exporter created {} as a non-regular file",
            path.display()
        ))
        .into());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode != 0o600 {
        return Err(e2e_error(format!(
            "file exporter created {} with mode {mode:o}, expected 600",
            path.display()
        ))
        .into());
    }
    let records = read_file_records(path)?;
    let batches = decode_and_assert_file_records(&records)?;
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

fn read_file_records(path: &Path) -> Result<Vec<FileBatchRecord>, Box<dyn std::error::Error>> {
    let contents = fs::read_to_string(path)?;
    if contents.is_empty() {
        return Err(e2e_error("file exporter wrote no records").into());
    }
    if !contents.ends_with('\n') {
        return Err(e2e_error("file exporter record file did not end with a newline").into());
    }
    let records = contents
        .lines()
        .enumerate()
        .map(|(index, line)| {
            serde_json::from_str::<FileBatchRecord>(line).map_err(|source| {
                e2e_error(format!(
                    "file exporter record line {} was invalid JSON: {source}",
                    index + 1
                ))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(records)
}

fn decode_and_assert_file_records(
    records: &[FileBatchRecord],
) -> Result<Vec<BatchEnvelope>, Box<dyn std::error::Error>> {
    records
        .iter()
        .map(|record| {
            if record.kind != FileBatchRecordKind::ProtobufBatch {
                return Err(e2e_error(format!(
                    "file exporter record {} had unexpected kind {:?}",
                    record.batch_id, record.kind
                ))
                .into());
            }
            if record.agent_id != AGENT_ID {
                return Err(e2e_error(format!(
                    "file exporter record {} carried unexpected agent id {}",
                    record.batch_id, record.agent_id
                ))
                .into());
            }
            if record.codec != TEST_CODEC {
                return Err(e2e_error(format!(
                    "file exporter record {} used codec {:?}, expected {:?}",
                    record.batch_id, record.codec, TEST_CODEC
                ))
                .into());
            }
            let payload = record.decode_payload()?;
            let batch = BatchEnvelope::decode_from_slice(&payload)?;
            assert_file_record_matches_batch(record, &batch)?;
            Ok(batch)
        })
        .collect()
}

fn assert_file_record_matches_batch(
    record: &FileBatchRecord,
    batch: &BatchEnvelope,
) -> Result<(), Box<dyn std::error::Error>> {
    if batch.codec != TEST_CODEC.wire_name() {
        return Err(e2e_error(format!(
            "file exporter batch {} carried codec {}, expected {}",
            batch.batch_id,
            batch.codec,
            TEST_CODEC.wire_name()
        ))
        .into());
    }
    if batch.batch_id != record.batch_id {
        return Err(e2e_error(format!(
            "file exporter record id {} did not match decoded batch id {}",
            record.batch_id, batch.batch_id
        ))
        .into());
    }
    if batch.events.len() != record.event_count {
        return Err(e2e_error(format!(
            "file exporter record {} declared {} events, decoded {}",
            record.batch_id,
            record.event_count,
            batch.events.len()
        ))
        .into());
    }
    let Some(first_sequence) = batch.events.first().map(|event| event.sequence) else {
        return Err(e2e_error(format!(
            "file exporter record {} decoded to an empty batch",
            record.batch_id
        ))
        .into());
    };
    let last_sequence = batch
        .events
        .last()
        .map(|event| event.sequence)
        .expect("non-empty batch has a last event");
    let expected_batch_id = expected_batch_id(AGENT_ID, FILE_SINK, first_sequence, last_sequence);
    if (
        record.first_sequence,
        record.last_sequence,
        record.batch_id.as_str(),
    ) != (first_sequence, last_sequence, expected_batch_id.as_str())
    {
        return Err(e2e_error(format!(
            "file exporter record {} metadata did not match decoded batch range {first_sequence}-{last_sequence}",
            record.batch_id
        ))
        .into());
    }
    Ok(())
}
