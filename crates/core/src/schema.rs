use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SpoolPayloadSchema {
    CaptureBytesJsonV1,
    EventEnvelopeJsonV1,
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
    pub const CAPTURE_BYTES_JSON_V1: &'static str = "sssa.probe.capture_bytes.v1.json";
    pub const EVENT_ENVELOPE_JSON_V1: &'static str = "sssa.probe.event_envelope.v1.json";

    pub fn from_wire(value: impl AsRef<str>) -> Self {
        let value = value.as_ref();
        match value {
            Self::CAPTURE_BYTES_JSON_V1 => Self::CaptureBytesJsonV1,
            Self::EVENT_ENVELOPE_JSON_V1 => Self::EventEnvelopeJsonV1,
            _ => Self::Other(UnknownSpoolPayloadSchema(value.to_string())),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::CaptureBytesJsonV1 => Self::CAPTURE_BYTES_JSON_V1,
            Self::EventEnvelopeJsonV1 => Self::EVENT_ENVELOPE_JSON_V1,
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
            SpoolPayloadSchema::from_wire(SpoolPayloadSchema::CAPTURE_BYTES_JSON_V1),
            SpoolPayloadSchema::CaptureBytesJsonV1
        );
        assert_eq!(
            SpoolPayloadSchema::CaptureBytesJsonV1.as_str(),
            SpoolPayloadSchema::CAPTURE_BYTES_JSON_V1
        );
        assert_eq!(
            SpoolPayloadSchema::from_wire(SpoolPayloadSchema::EVENT_ENVELOPE_JSON_V1),
            SpoolPayloadSchema::EventEnvelopeJsonV1
        );
        assert_eq!(
            SpoolPayloadSchema::EventEnvelopeJsonV1.as_str(),
            SpoolPayloadSchema::EVENT_ENVELOPE_JSON_V1
        );
    }

    #[test]
    fn unknown_schema_preserves_wire_name() {
        let schema = SpoolPayloadSchema::from_wire("custom.schema.v1");

        assert!(matches!(schema, SpoolPayloadSchema::Other(_)));
        assert_eq!(schema.as_str(), "custom.schema.v1");
    }
}
