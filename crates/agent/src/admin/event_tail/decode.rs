use probe_core::{
    CaptureOrigin, Direction, EventEnvelope, EventId, FlowContext, SpoolPayloadSchema, Timestamp,
    WebSocketMessageOpcode,
};
use serde::{
    Deserialize, Deserializer,
    de::{self, SeqAccess, Visitor},
};
use storage::StoredEvent;

use super::{error::EventTailError, model::*};

impl<'de> Deserialize<'de> for EventTailEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = EventTailEventParts::deserialize(deserializer)?;
        Ok(Self {
            id: parts.id,
            timestamp: parts.timestamp,
            origin: parts.origin,
            config_version: parts.config_version,
            policy_version: parts.policy_version,
            degraded: parts.degraded,
            flow: parts
                .flow
                .or_else(|| parts.subject.and_then(EventTailSubject::into_flow)),
            kind: parts.kind,
        })
    }
}

#[derive(Deserialize)]
struct EventTailEventParts {
    id: EventId,
    timestamp: Timestamp,
    origin: CaptureOrigin,
    config_version: String,
    #[serde(default)]
    policy_version: Option<String>,
    #[serde(default)]
    degraded: bool,
    #[serde(default)]
    flow: Option<FlowContext>,
    #[serde(default)]
    subject: Option<EventTailSubject>,
    kind: EventTailKind,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum EventTailSubject {
    Flow { flow: Box<FlowContext> },
    Provider,
}

impl EventTailSubject {
    fn into_flow(self) -> Option<FlowContext> {
        match self {
            Self::Flow { flow } => Some(*flow),
            Self::Provider => None,
        }
    }
}

impl<'de> Deserialize<'de> for EventTailBodyChunk {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = EventTailBodyChunkParts::deserialize(deserializer)?;
        Ok(Self {
            direction: parts.direction,
            stream_sequence: parts.stream_sequence,
            offset: parts.offset,
            data_len: parts
                .data_len
                .or(parts.data.map(|data| data.len))
                .ok_or_else(|| de::Error::missing_field("data_len"))?,
            end_stream: parts.end_stream,
        })
    }
}

#[derive(Deserialize)]
struct EventTailBodyChunkParts {
    direction: Direction,
    stream_sequence: u64,
    offset: u64,
    #[serde(default)]
    data_len: Option<usize>,
    #[serde(default)]
    data: Option<JsonPayloadLength>,
    end_stream: bool,
}

impl<'de> Deserialize<'de> for EventTailSseEvent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = EventTailSseEventParts::deserialize(deserializer)?;
        Ok(Self {
            direction: parts.direction,
            stream_sequence: parts.stream_sequence,
            event: parts.event,
            id: parts.id,
            retry_ms: parts.retry_ms,
            data_len: parts
                .data_len
                .or(parts.data.map(|data| data.len))
                .ok_or_else(|| de::Error::missing_field("data_len"))?,
        })
    }
}

#[derive(Deserialize)]
struct EventTailSseEventParts {
    direction: Direction,
    stream_sequence: u64,
    event: Option<String>,
    id: Option<String>,
    retry_ms: Option<u64>,
    #[serde(default)]
    data_len: Option<usize>,
    #[serde(default)]
    data: Option<JsonStringLength>,
}

impl<'de> Deserialize<'de> for EventTailWebSocketMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let parts = EventTailWebSocketMessageParts::deserialize(deserializer)?;
        Ok(Self {
            direction: parts.direction,
            stream_sequence: parts.stream_sequence,
            message_sequence: parts.message_sequence,
            first_frame_sequence: parts.first_frame_sequence,
            final_frame_sequence: parts.final_frame_sequence,
            opcode: parts.opcode,
            payload_len: parts.payload_len,
            payload_fingerprint: parts.payload_fingerprint,
        })
    }
}

#[derive(Deserialize)]
struct EventTailWebSocketMessageParts {
    direction: Direction,
    stream_sequence: u64,
    message_sequence: u64,
    first_frame_sequence: u64,
    final_frame_sequence: u64,
    opcode: WebSocketMessageOpcode,
    payload_len: u64,
    #[serde(default, rename = "payload")]
    _payload: Option<de::IgnoredAny>,
    payload_fingerprint: Vec<u8>,
}

struct JsonPayloadLength {
    len: usize,
}

impl<'de> Deserialize<'de> for JsonPayloadLength {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonPayloadLengthVisitor)
    }
}

struct JsonPayloadLengthVisitor;

impl<'de> Visitor<'de> for JsonPayloadLengthVisitor {
    type Value = JsonPayloadLength;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON byte payload")
    }

    fn visit_borrowed_bytes<E>(self, value: &'de [u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonPayloadLength { len: value.len() })
    }

    fn visit_bytes<E>(self, value: &[u8]) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonPayloadLength { len: value.len() })
    }

    fn visit_byte_buf<E>(self, value: Vec<u8>) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonPayloadLength { len: value.len() })
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonPayloadLength {
            len: base64_decoded_len(value),
        })
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonPayloadLength {
            len: base64_decoded_len(value),
        })
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonPayloadLength {
            len: base64_decoded_len(&value),
        })
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut len = 0_usize;
        while seq.next_element::<de::IgnoredAny>()?.is_some() {
            len = len.saturating_add(1);
        }
        Ok(JsonPayloadLength { len })
    }
}

struct JsonStringLength {
    len: usize,
}

impl<'de> Deserialize<'de> for JsonStringLength {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonStringLengthVisitor)
    }
}

struct JsonStringLengthVisitor;

impl<'de> Visitor<'de> for JsonStringLengthVisitor {
    type Value = JsonStringLength;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a JSON string")
    }

    fn visit_borrowed_str<E>(self, value: &'de str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonStringLength { len: value.len() })
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonStringLength { len: value.len() })
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Ok(JsonStringLength { len: value.len() })
    }
}

fn base64_decoded_len(value: &str) -> usize {
    let len = value.len();
    let padding = value
        .as_bytes()
        .iter()
        .rev()
        .take_while(|byte| **byte == b'=')
        .count();
    len.saturating_mul(3)
        .checked_div(4)
        .unwrap_or_default()
        .saturating_sub(padding)
}
pub(super) struct DecodedStoredEvent {
    pub(super) sequence: u64,
    pub(super) stored_at_unix_ns: u64,
    pub(super) event: EventEnvelope,
}

pub(super) fn decode_tail_record(stored: StoredEvent) -> Result<EventTailRecord, EventTailError> {
    let schema = stored.payload.schema();
    if schema != &SpoolPayloadSchema::EventEnvelopeSubjectOriginJson {
        return Err(EventTailError::UnexpectedSchema {
            sequence: stored.sequence,
            expected: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON,
            actual: schema.to_string(),
        });
    }
    let event = serde_json::from_slice(stored.payload.bytes())?;
    Ok(EventTailRecord {
        sequence: stored.sequence,
        stored_at_unix_ns: stored.stored_at_unix_ns,
        event,
    })
}

pub(super) fn decode_stored_event(
    stored: StoredEvent,
) -> Result<DecodedStoredEvent, EventTailError> {
    let schema = stored.payload.schema();
    if schema != &SpoolPayloadSchema::EventEnvelopeSubjectOriginJson {
        return Err(EventTailError::UnexpectedSchema {
            sequence: stored.sequence,
            expected: SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON,
            actual: schema.to_string(),
        });
    }
    let event = serde_json::from_slice(stored.payload.bytes())?;
    Ok(DecodedStoredEvent {
        sequence: stored.sequence,
        stored_at_unix_ns: stored.stored_at_unix_ns,
        event,
    })
}
