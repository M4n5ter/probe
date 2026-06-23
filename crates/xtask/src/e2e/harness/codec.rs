use capture::CaptureEvent;
use probe_core::{EventEnvelope, SpoolPayloadSchema};
use storage::StoredEvent;

use super::e2e_error;

pub(crate) fn decode_capture_event(
    event: &StoredEvent,
) -> Result<CaptureEvent, Box<dyn std::error::Error>> {
    if event.payload.schema() != &SpoolPayloadSchema::CaptureEventOriginJson {
        return Err(e2e_error(format!(
            "ingress record {} used unexpected schema {}",
            event.sequence,
            event.payload.schema_wire()
        ))
        .into());
    }
    serde_json::from_slice::<CaptureEvent>(event.payload.bytes()).map_err(Into::into)
}

pub(crate) fn decode_envelope(
    event: &StoredEvent,
) -> Result<EventEnvelope, Box<dyn std::error::Error>> {
    if event.payload.schema() != &SpoolPayloadSchema::EventEnvelopeSubjectOriginJson {
        return Err(e2e_error(format!(
            "export record {} used unexpected schema {}",
            event.sequence,
            event.payload.schema_wire()
        ))
        .into());
    }
    serde_json::from_slice::<EventEnvelope>(event.payload.bytes()).map_err(Into::into)
}
