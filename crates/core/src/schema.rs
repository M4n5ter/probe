use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpoolPayloadSchema {
    CaptureEventJson,
    EventEnvelopeJson,
    Other(UnknownSpoolPayloadSchema),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnknownSpoolPayloadSchema(String);

impl UnknownSpoolPayloadSchema {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl SpoolPayloadSchema {
    pub const CAPTURE_EVENT_JSON: &'static str = "sssa.probe.capture_event.json";
    pub const EVENT_ENVELOPE_JSON: &'static str = "sssa.probe.event_envelope.json";

    pub fn from_wire(value: impl AsRef<str>) -> Self {
        let value = value.as_ref();
        match value {
            Self::CAPTURE_EVENT_JSON => Self::CaptureEventJson,
            Self::EVENT_ENVELOPE_JSON => Self::EventEnvelopeJson,
            _ => Self::Other(UnknownSpoolPayloadSchema(value.to_string())),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::CaptureEventJson => Self::CAPTURE_EVENT_JSON,
            Self::EventEnvelopeJson => Self::EVENT_ENVELOPE_JSON,
            Self::Other(value) => value.as_str(),
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
    fn known_schema_round_trips_to_wire_name() {
        assert_eq!(
            SpoolPayloadSchema::from_wire(SpoolPayloadSchema::CAPTURE_EVENT_JSON),
            SpoolPayloadSchema::CaptureEventJson
        );
        assert_eq!(
            SpoolPayloadSchema::CaptureEventJson.as_str(),
            SpoolPayloadSchema::CAPTURE_EVENT_JSON
        );
        assert_eq!(
            SpoolPayloadSchema::from_wire(SpoolPayloadSchema::EVENT_ENVELOPE_JSON),
            SpoolPayloadSchema::EventEnvelopeJson
        );
        assert_eq!(
            SpoolPayloadSchema::EventEnvelopeJson.as_str(),
            SpoolPayloadSchema::EVENT_ENVELOPE_JSON
        );
    }

    #[test]
    fn unknown_schema_preserves_wire_name() {
        let schema = SpoolPayloadSchema::from_wire("custom.schema.v1");

        assert!(matches!(schema, SpoolPayloadSchema::Other(_)));
        assert_eq!(schema.as_str(), "custom.schema.v1");
    }
}
