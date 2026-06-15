use std::fmt;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpoolPayloadSchema {
    CaptureEventJson,
    EventEnvelopeJson,
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
    pub const CAPTURE_EVENT_JSON: &'static str = "sssa.probe.capture_event.json";
    pub const EVENT_ENVELOPE_JSON: &'static str = "sssa.probe.event_envelope.json";

    pub fn from_wire(value: impl AsRef<str>) -> Result<Self, SpoolPayloadSchemaError> {
        let value = value.as_ref();
        match value {
            Self::CAPTURE_EVENT_JSON => Ok(Self::CaptureEventJson),
            Self::EVENT_ENVELOPE_JSON => Ok(Self::EventEnvelopeJson),
            _ => Err(SpoolPayloadSchemaError {
                value: value.to_string(),
            }),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::CaptureEventJson => Self::CAPTURE_EVENT_JSON,
            Self::EventEnvelopeJson => Self::EVENT_ENVELOPE_JSON,
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
            SpoolPayloadSchema::from_wire(SpoolPayloadSchema::CAPTURE_EVENT_JSON)?,
            SpoolPayloadSchema::CaptureEventJson
        );
        assert_eq!(
            SpoolPayloadSchema::CaptureEventJson.as_str(),
            SpoolPayloadSchema::CAPTURE_EVENT_JSON
        );
        assert_eq!(
            SpoolPayloadSchema::from_wire(SpoolPayloadSchema::EVENT_ENVELOPE_JSON)?,
            SpoolPayloadSchema::EventEnvelopeJson
        );
        assert_eq!(
            SpoolPayloadSchema::EventEnvelopeJson.as_str(),
            SpoolPayloadSchema::EVENT_ENVELOPE_JSON
        );

        Ok(())
    }

    #[test]
    fn unknown_schema_is_rejected() {
        let error = SpoolPayloadSchema::from_wire("custom.schema.extra")
            .expect_err("unknown spool payload schema must fail");

        assert_eq!(error.value(), "custom.schema.extra");
    }
}
