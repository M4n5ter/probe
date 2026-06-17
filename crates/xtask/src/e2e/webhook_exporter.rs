use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::Path,
    process::ExitCode,
};

use exporter::CompressionCodec;
use probe_config::{CompressionCodecName, ExporterConfig, ExporterTransport};
use probe_core::{CaptureSource, EventEnvelope, EventKind, SpoolPayloadSchema};
use proto::PayloadFormat;
use storage::FjallSpool;

use super::harness::{e2e_error, run_agent_with_max_events, run_with_temp_root};
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
    assert_export_cursor(&spool_path, expected_cursor)?;

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
            "sssa-e2e-export",
            "/usr/bin/sssa-e2e-export",
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
        transport: ExporterTransport::Webhook,
        endpoint,
        codec: test_codec_name(),
        headers: BTreeMap::from([("x-sssa-e2e".to_string(), "webhook-exporter".to_string())]),
        tls: Default::default(),
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
            .get("x-sssa-e2e")
            .is_some_and(|value| value == "webhook-exporter")
    }) {
        return Err(e2e_error("webhook receiver did not observe configured header").into());
    }

    let expected_cursor = assert_batch_sequence_contract(batches)?;
    let envelopes = decode_and_assert_event_records(batches)?;
    assert_expected_export_set(&envelopes, scenario)?;

    println!(
        "e2e webhook exporter observed {} HTTP requests carrying {} exported events",
        batches.len(),
        envelopes.len()
    );
    Ok(expected_cursor)
}

fn assert_batch_sequence_contract(
    batches: &[ReceivedBatch],
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut all_sequences = Vec::new();
    for batch in batches {
        if batch.batch.agent_id != AGENT_ID {
            return Err(e2e_error(format!(
                "batch {} carried unexpected agent id {}",
                batch.batch.batch_id, batch.batch.agent_id
            ))
            .into());
        }
        let Some(first_sequence) = batch.batch.events.first().map(|event| event.sequence) else {
            return Err(e2e_error("webhook receiver observed an empty batch").into());
        };
        let last_sequence = batch
            .batch
            .events
            .last()
            .map(|event| event.sequence)
            .expect("non-empty batch has a last event");
        let expected_batch_id = expected_batch_id(first_sequence, last_sequence);
        if batch.batch.batch_id != expected_batch_id {
            return Err(e2e_error(format!(
                "batch id {} did not match expected range id {expected_batch_id}",
                batch.batch.batch_id
            ))
            .into());
        }
        let batch_sequences = batch
            .batch
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>();
        let expected_batch_sequences = (first_sequence..=last_sequence).collect::<Vec<_>>();
        if batch_sequences != expected_batch_sequences {
            return Err(e2e_error(format!(
                "batch {} has non-contiguous sequences {:?}",
                batch.batch.batch_id, batch_sequences
            ))
            .into());
        }
        for event in &batch.batch.events {
            if event.payload_format() != PayloadFormat::Json {
                return Err(e2e_error(format!(
                    "batch {} carried non-json payload format at sequence {}",
                    batch.batch.batch_id, event.sequence
                ))
                .into());
            }
            if event.payload_schema != SpoolPayloadSchema::EventEnvelopeJson.as_str() {
                return Err(e2e_error(format!(
                    "batch {} carried unexpected payload schema {} at sequence {}",
                    batch.batch.batch_id, event.payload_schema, event.sequence
                ))
                .into());
            }
        }
        all_sequences.extend(batch_sequences);
    }

    let unique_sequences = all_sequences.iter().copied().collect::<BTreeSet<_>>();
    if unique_sequences.len() != all_sequences.len() {
        return Err(e2e_error(format!(
            "webhook batches carried duplicate export sequences {all_sequences:?}"
        ))
        .into());
    }
    let expected_sequences = (1..=u64::try_from(PLAINTEXT_FEED_EXPORT_EVENT_COUNT)
        .unwrap_or(u64::MAX))
        .collect::<BTreeSet<_>>();
    if unique_sequences != expected_sequences {
        return Err(e2e_error(format!(
            "webhook batches carried export sequences {:?}, expected {:?}",
            unique_sequences, expected_sequences
        ))
        .into());
    }
    unique_sequences
        .last()
        .copied()
        .ok_or_else(|| e2e_error("webhook receiver observed no export sequences").into())
}

fn expected_batch_id(first_sequence: u64, last_sequence: u64) -> String {
    format!("{AGENT_ID}:{COLLECTOR_SINK}:{first_sequence}-{last_sequence}")
}

fn test_codec_name() -> CompressionCodecName {
    match TEST_CODEC {
        CompressionCodec::None => CompressionCodecName::None,
        CompressionCodec::Zstd => CompressionCodecName::Zstd,
        CompressionCodec::Gzip => CompressionCodecName::Gzip,
        CompressionCodec::Deflate => CompressionCodecName::Deflate,
    }
}

fn decode_and_assert_event_records(
    batches: &[ReceivedBatch],
) -> Result<Vec<EventEnvelope>, Box<dyn std::error::Error>> {
    batches
        .iter()
        .flat_map(|batch| {
            batch
                .batch
                .events
                .iter()
                .map(|record| (&batch.batch, record))
        })
        .map(|(batch, record)| {
            let envelope = serde_json::from_slice::<EventEnvelope>(&record.payload)?;
            if record.event_id != envelope.id.0 {
                return Err(e2e_error(format!(
                    "batch {} record event id {} did not match payload envelope id {}",
                    batch.batch_id, record.event_id, envelope.id.0
                ))
                .into());
            }
            Ok(envelope)
        })
        .collect()
}

fn assert_expected_export_set(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedScenario,
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes.len() != PLAINTEXT_FEED_EXPORT_EVENT_COUNT {
        return Err(e2e_error(format!(
            "expected {PLAINTEXT_FEED_EXPORT_EVENT_COUNT} exported events, got {}",
            envelopes.len()
        ))
        .into());
    }
    let expected_flow_id = scenario.expected_flow_id();
    if !envelopes.iter().all(|envelope| {
        envelope.source == CaptureSource::ExternalPlaintextFeed
            && envelope.flow.id.0 == expected_flow_id
    }) {
        return Err(e2e_error("webhook batch carried an unexpected source or flow").into());
    }

    let request_count = envelopes
        .iter()
        .filter(|envelope| {
            matches!(
                &envelope.kind,
                EventKind::HttpRequestHeaders(headers)
                    if headers.method.as_deref() == Some("GET")
                        && headers.target.as_deref() == Some(scenario.request_target())
            )
        })
        .count();
    let expected_policy_version = scenario.expected_policy_version();
    let expected_alert = scenario.expected_policy_alert_message();
    let policy_alert_count = envelopes
        .iter()
        .filter(|envelope| {
            envelope.policy_version.as_deref() == Some(expected_policy_version.as_str())
                && matches!(
                    &envelope.kind,
                    EventKind::PolicyAlert(alert) if alert.message == expected_alert
                )
        })
        .count();
    let opened_count = envelopes
        .iter()
        .filter(|envelope| matches!(envelope.kind, EventKind::ConnectionOpened))
        .count();
    let closed_count = envelopes
        .iter()
        .filter(|envelope| matches!(envelope.kind, EventKind::ConnectionClosed))
        .count();

    if (
        request_count,
        policy_alert_count,
        opened_count,
        closed_count,
    ) != (1, 1, 1, 1)
    {
        return Err(e2e_error(format!(
            "unexpected export event set: request={request_count}, policy_alert={policy_alert_count}, opened={opened_count}, closed={closed_count}"
        ))
        .into());
    }
    Ok(())
}

fn assert_export_cursor(
    spool_path: &Path,
    expected_cursor: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let pending = spool.read_export_batch(COLLECTOR_SINK, 64)?;
    if !pending.is_empty() {
        return Err(e2e_error(format!(
            "expected acked collector sink queue to be empty, got {} pending records",
            pending.len()
        ))
        .into());
    }
    let cursor = spool.export_cursor(COLLECTOR_SINK)?;
    if cursor != expected_cursor {
        return Err(e2e_error(format!(
            "collector sink cursor advanced to {cursor}, expected {expected_cursor}"
        ))
        .into());
    }
    Ok(())
}
