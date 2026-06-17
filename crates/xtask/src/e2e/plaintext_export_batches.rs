use std::{collections::BTreeSet, path::Path};

use exporter::CompressionCodec;
use probe_config::CompressionCodecName;
use probe_core::{
    CaptureProviderKind, CaptureSource, EventEnvelope, EventKind, SpoolPayloadSchema,
};
use proto::{BatchEnvelope, PayloadFormat};
use storage::FjallSpool;

use super::harness::e2e_error;
use super::plaintext_scenario::{PLAINTEXT_FEED_EXPORT_EVENT_COUNT, PlaintextFeedScenario};

pub(crate) fn compression_codec_name(codec: CompressionCodec) -> CompressionCodecName {
    match codec {
        CompressionCodec::None => CompressionCodecName::None,
        CompressionCodec::Zstd => CompressionCodecName::Zstd,
        CompressionCodec::Gzip => CompressionCodecName::Gzip,
        CompressionCodec::Deflate => CompressionCodecName::Deflate,
    }
}

pub(crate) fn expected_batch_id(
    agent_id: &str,
    sink_id: &str,
    first_sequence: u64,
    last_sequence: u64,
) -> String {
    format!("{agent_id}:{sink_id}:{first_sequence}-{last_sequence}")
}

pub(crate) fn assert_batch_sequence_contract(
    batches: &[BatchEnvelope],
    agent_id: &str,
    sink_id: &str,
    label: &str,
) -> Result<u64, Box<dyn std::error::Error>> {
    let mut all_sequences = Vec::new();
    for batch in batches {
        if batch.agent_id != agent_id {
            return Err(e2e_error(format!(
                "{label} batch {} carried unexpected agent id {}",
                batch.batch_id, batch.agent_id
            ))
            .into());
        }
        let Some(first_sequence) = batch.events.first().map(|event| event.sequence) else {
            return Err(e2e_error(format!("{label} observed an empty batch")).into());
        };
        let last_sequence = batch
            .events
            .last()
            .map(|event| event.sequence)
            .expect("non-empty batch has a last event");
        let expected_batch_id = expected_batch_id(agent_id, sink_id, first_sequence, last_sequence);
        if batch.batch_id != expected_batch_id {
            return Err(e2e_error(format!(
                "{label} batch id {} did not match expected range id {expected_batch_id}",
                batch.batch_id
            ))
            .into());
        }
        let batch_sequences = batch
            .events
            .iter()
            .map(|event| event.sequence)
            .collect::<Vec<_>>();
        let expected_batch_sequences = (first_sequence..=last_sequence).collect::<Vec<_>>();
        if batch_sequences != expected_batch_sequences {
            return Err(e2e_error(format!(
                "{label} batch {} has non-contiguous sequences {:?}",
                batch.batch_id, batch_sequences
            ))
            .into());
        }
        for event in &batch.events {
            if event.payload_format() != PayloadFormat::Json {
                return Err(e2e_error(format!(
                    "{label} batch {} carried non-json payload format at sequence {}",
                    batch.batch_id, event.sequence
                ))
                .into());
            }
            if event.payload_schema != SpoolPayloadSchema::EventEnvelopeSubjectOriginJson.as_str() {
                return Err(e2e_error(format!(
                    "{label} batch {} carried unexpected payload schema {} at sequence {}",
                    batch.batch_id, event.payload_schema, event.sequence
                ))
                .into());
            }
        }
        all_sequences.extend(batch_sequences);
    }

    let unique_sequences = all_sequences.iter().copied().collect::<BTreeSet<_>>();
    if unique_sequences.len() != all_sequences.len() {
        return Err(e2e_error(format!(
            "{label} carried duplicate export sequences {all_sequences:?}"
        ))
        .into());
    }
    let expected_sequences = (1..=u64::try_from(PLAINTEXT_FEED_EXPORT_EVENT_COUNT)
        .unwrap_or(u64::MAX))
        .collect::<Vec<_>>();
    if all_sequences != expected_sequences {
        return Err(e2e_error(format!(
            "{label} carried export sequences in order {:?}, expected {:?}",
            all_sequences, expected_sequences
        ))
        .into());
    }
    all_sequences
        .last()
        .copied()
        .ok_or_else(|| e2e_error(format!("{label} observed no export sequences")).into())
}

pub(crate) fn decode_and_assert_event_records(
    batches: &[BatchEnvelope],
    label: &str,
) -> Result<Vec<EventEnvelope>, Box<dyn std::error::Error>> {
    batches
        .iter()
        .flat_map(|batch| batch.events.iter().map(move |record| (batch, record)))
        .map(|(batch, record)| {
            let envelope = serde_json::from_slice::<EventEnvelope>(&record.payload)?;
            if record.event_id != envelope.id().as_str() {
                return Err(e2e_error(format!(
                    "{label} batch {} record event id {} did not match payload envelope id {}",
                    batch.batch_id,
                    record.event_id,
                    envelope.id().as_str()
                ))
                .into());
            }
            Ok(envelope)
        })
        .collect()
}

pub(crate) fn assert_expected_export_set(
    envelopes: &[EventEnvelope],
    scenario: &PlaintextFeedScenario,
    label: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if envelopes.len() != PLAINTEXT_FEED_EXPORT_EVENT_COUNT {
        return Err(e2e_error(format!(
            "{label} expected {PLAINTEXT_FEED_EXPORT_EVENT_COUNT} exported events, got {}",
            envelopes.len()
        ))
        .into());
    }
    let expected_flow_id = scenario.expected_flow_id();
    if !envelopes.iter().all(|envelope| {
        envelope.origin().source() == CaptureSource::ExternalPlaintextFeed
            && envelope.origin().provider() == CaptureProviderKind::Plaintext
            && envelope
                .flow()
                .is_some_and(|flow| flow.id.0 == expected_flow_id)
    }) {
        return Err(e2e_error(format!("{label} carried an unexpected source or flow")).into());
    }

    let request_count = envelopes
        .iter()
        .filter(|envelope| {
            matches!(
                envelope.kind(),
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
            envelope.policy_version() == Some(expected_policy_version.as_str())
                && matches!(
                    envelope.kind(),
                    EventKind::PolicyAlert(alert) if alert.message == expected_alert
                )
        })
        .count();
    let opened_count = envelopes
        .iter()
        .filter(|envelope| matches!(envelope.kind(), EventKind::ConnectionOpened))
        .count();
    let closed_count = envelopes
        .iter()
        .filter(|envelope| matches!(envelope.kind(), EventKind::ConnectionClosed))
        .count();

    if (
        request_count,
        policy_alert_count,
        opened_count,
        closed_count,
    ) != (1, 1, 1, 1)
    {
        return Err(e2e_error(format!(
            "{label} unexpected export event set: request={request_count}, policy_alert={policy_alert_count}, opened={opened_count}, closed={closed_count}"
        ))
        .into());
    }
    Ok(())
}

pub(crate) fn assert_export_cursor(
    spool_path: &Path,
    sink_id: &str,
    expected_cursor: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let spool = FjallSpool::open(spool_path)?;
    let pending = spool.read_export_batch(sink_id, 64)?;
    if !pending.is_empty() {
        return Err(e2e_error(format!(
            "expected acked {sink_id} sink queue to be empty, got {} pending records",
            pending.len()
        ))
        .into());
    }
    let cursor = spool.export_cursor(sink_id)?;
    if cursor != expected_cursor {
        return Err(e2e_error(format!(
            "{sink_id} sink cursor advanced to {cursor}, expected {expected_cursor}"
        ))
        .into());
    }
    Ok(())
}
