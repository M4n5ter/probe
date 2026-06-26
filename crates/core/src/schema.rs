use std::fmt;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpoolPayloadSchema {
    CaptureEventOriginJson,
    EventEnvelopeSubjectOriginJson,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("unsupported spool payload schema: {value}")]
pub struct SpoolPayloadSchemaError {
    value: String,
}

impl SpoolPayloadSchemaError {
    pub fn value(&self) -> &str {
        &self.value
    }
}

impl SpoolPayloadSchema {
    pub const CAPTURE_EVENT_ORIGIN_JSON: &'static str = "traffic.probe.capture_event.origin.json";
    pub const EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON: &'static str =
        "traffic.probe.event_envelope.subject_origin.json";

    pub fn from_wire(value: impl AsRef<str>) -> Result<Self, SpoolPayloadSchemaError> {
        let value = value.as_ref();
        match value {
            Self::CAPTURE_EVENT_ORIGIN_JSON => Ok(Self::CaptureEventOriginJson),
            Self::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON => Ok(Self::EventEnvelopeSubjectOriginJson),
            _ => Err(SpoolPayloadSchemaError {
                value: value.to_string(),
            }),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::CaptureEventOriginJson => Self::CAPTURE_EVENT_ORIGIN_JSON,
            Self::EventEnvelopeSubjectOriginJson => Self::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON,
        }
    }
}

impl fmt::Display for SpoolPayloadSchema {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_schema_round_trips_to_wire_name() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            SpoolPayloadSchema::from_wire(SpoolPayloadSchema::CAPTURE_EVENT_ORIGIN_JSON)?,
            SpoolPayloadSchema::CaptureEventOriginJson
        );
        assert_eq!(
            SpoolPayloadSchema::CaptureEventOriginJson.as_str(),
            SpoolPayloadSchema::CAPTURE_EVENT_ORIGIN_JSON
        );
        assert_eq!(
            SpoolPayloadSchema::from_wire(SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON)?,
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson
        );
        assert_eq!(
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson.as_str(),
            SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON
        );

        Ok(())
    }

    #[test]
    fn unknown_schema_is_rejected() {
        let error = SpoolPayloadSchema::from_wire("custom.schema.extra")
            .expect_err("unknown spool payload schema must fail");

        assert_eq!(error.value(), "custom.schema.extra");
    }

    #[test]
    fn old_capture_event_schema_name_is_rejected() {
        let error = SpoolPayloadSchema::from_wire("traffic.probe.capture_event.json")
            .expect_err("old capture event schema name must fail");

        assert_eq!(error.value(), "traffic.probe.capture_event.json");
    }
}
