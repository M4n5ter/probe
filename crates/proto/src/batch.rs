use probe_core::{EventEnvelope, SpoolPayloadSchema};
use prost::{Enumeration, Message};
use thiserror::Error;

#[derive(Clone, PartialEq, Message)]
pub struct BatchEnvelope {
    #[prost(string, tag = "1")]
    pub batch_id: String,
    #[prost(string, tag = "2")]
    pub agent_id: String,
    #[prost(string, tag = "3")]
    pub codec: String,
    #[prost(message, repeated, tag = "4")]
    pub events: Vec<EventRecord>,
}

#[derive(Clone, PartialEq, Message)]
pub struct EventRecord {
    #[prost(string, tag = "1")]
    pub event_id: String,
    #[prost(uint64, tag = "2")]
    pub sequence: u64,
    #[prost(enumeration = "PayloadFormat", tag = "3")]
    pub payload_format: i32,
    #[prost(bytes, tag = "4")]
    pub payload: Vec<u8>,
    #[prost(string, tag = "5")]
    pub payload_schema: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Enumeration)]
#[repr(i32)]
pub enum PayloadFormat {
    Json = 0,
}

#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("failed to serialize event envelope: {0}")]
    Json(#[from] serde_json::Error),
    #[error("failed to decode protobuf batch: {0}")]
    Decode(#[from] prost::DecodeError),
}

impl BatchEnvelope {
    pub fn from_events(
        batch_id: impl Into<String>,
        agent_id: impl Into<String>,
        codec: impl Into<String>,
        events: impl IntoIterator<Item = (u64, EventEnvelope)>,
    ) -> Result<Self, ProtoError> {
        let records = events
            .into_iter()
            .map(|(sequence, event)| {
                let event_id = event.id().as_str().to_string();
                serde_json::to_vec(&event)
                    .map(|payload| json_event_envelope_record(sequence, event_id, payload))
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            batch_id: batch_id.into(),
            agent_id: agent_id.into(),
            codec: codec.into(),
            events: records,
        })
    }

    pub fn from_json_payloads<P>(
        batch_id: impl Into<String>,
        agent_id: impl Into<String>,
        codec: impl Into<String>,
        events: impl IntoIterator<Item = (u64, P)>,
    ) -> Result<Self, ProtoError>
    where
        P: AsRef<[u8]>,
    {
        let records = events
            .into_iter()
            .map(|(sequence, payload)| {
                let payload = payload.as_ref();
                let event = serde_json::from_slice::<EventEnvelope>(payload)?;
                Ok(json_event_envelope_record(
                    sequence,
                    event.id().as_str().to_string(),
                    payload.to_vec(),
                ))
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()?;

        Ok(Self {
            batch_id: batch_id.into(),
            agent_id: agent_id.into(),
            codec: codec.into(),
            events: records,
        })
    }

    pub fn encode_to_vec(&self) -> Vec<u8> {
        Message::encode_to_vec(self)
    }

    pub fn decode_from_slice(bytes: &[u8]) -> Result<Self, ProtoError> {
        Self::decode(bytes).map_err(ProtoError::Decode)
    }
}

fn json_event_envelope_record(sequence: u64, event_id: String, payload: Vec<u8>) -> EventRecord {
    EventRecord {
        event_id,
        sequence,
        payload_format: PayloadFormat::Json as i32,
        payload_schema: SpoolPayloadSchema::EventEnvelopeSubjectOriginJson.to_string(),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, EventEnvelope, EventKind,
        FlowContext, FlowIdentity, HttpHeaders, ProcessContext, ProcessIdentity,
        SpoolPayloadSchema, Timestamp, TransportProtocol,
    };

    use crate::{BatchEnvelope, EventRecord, PayloadFormat};

    #[test]
    fn encodes_and_decodes_batch_envelope() -> Result<(), Box<dyn std::error::Error>> {
        let batch = BatchEnvelope::from_events("batch-1", "agent-1", "none", [(1, demo_event())])?;
        let encoded = batch.encode_to_vec();
        let decoded = BatchEnvelope::decode_from_slice(&encoded)?;
        assert_eq!(decoded.batch_id, "batch-1");
        assert_eq!(decoded.events.len(), 1);
        assert_eq!(decoded.events[0].payload_format(), PayloadFormat::Json);
        assert_eq!(
            decoded.events[0].payload_schema,
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson.as_str()
        );
        Ok(())
    }

    #[test]
    fn builds_batch_from_spooled_json_payloads() -> Result<(), Box<dyn std::error::Error>> {
        let event = demo_event();
        let payload = serde_json::to_vec(&event)?;
        let batch = BatchEnvelope::from_json_payloads(
            "batch-1",
            "agent-1",
            "zstd",
            [(7, payload.as_slice())],
        )?;

        assert_eq!(batch.events[0].event_id, event.id().as_str());
        assert_eq!(batch.events[0].sequence, 7);
        assert_eq!(batch.events[0].payload_format(), PayloadFormat::Json);
        assert_eq!(
            batch.events[0].payload_schema,
            SpoolPayloadSchema::EventEnvelopeSubjectOriginJson.as_str()
        );
        Ok(())
    }

    #[test]
    fn published_export_batch_proto_matches_wire_contract() -> Result<(), String> {
        let schema = include_str!("../../../docs/export-batch.proto");
        let batch = export_batch_with_payload_format(PayloadFormat::Json as i32);

        assert_exact_schema(
            schema,
            [
                r#"syntax = "proto3";"#,
                "package probe.export;",
                "message BatchEnvelope {",
                "string batch_id = 1;",
                "string agent_id = 2;",
                "string codec = 3;",
                "repeated EventRecord events = 4;",
                "}",
                "message EventRecord {",
                "string event_id = 1;",
                "uint64 sequence = 2;",
                "PayloadFormat payload_format = 3;",
                "bytes payload = 4;",
                "string payload_schema = 5;",
                "}",
                "enum PayloadFormat {",
                "PAYLOAD_FORMAT_JSON = 0;",
                "}",
            ],
        )?;
        assert_eq!(PayloadFormat::Json as i32, 0);
        assert_eq!(
            batch.encode_to_vec(),
            [
                0x0a, 0x01, b'b', 0x12, 0x01, b'a', 0x1a, 0x04, b'n', b'o', b'n', b'e', 0x22, 0x0c,
                0x0a, 0x01, b'e', 0x10, 0x07, 0x22, 0x02, 0x01, 0x02, 0x2a, 0x01, b's',
            ]
        );
        assert_eq!(
            export_batch_with_payload_format(1).encode_to_vec(),
            [
                0x0a, 0x01, b'b', 0x12, 0x01, b'a', 0x1a, 0x04, b'n', b'o', b'n', b'e', 0x22, 0x0e,
                0x0a, 0x01, b'e', 0x10, 0x07, 0x18, 0x01, 0x22, 0x02, 0x01, 0x02, 0x2a, 0x01, b's',
            ]
        );
        Ok(())
    }

    fn export_batch_with_payload_format(payload_format: i32) -> BatchEnvelope {
        BatchEnvelope {
            batch_id: "b".to_string(),
            agent_id: "a".to_string(),
            codec: "none".to_string(),
            events: vec![EventRecord {
                event_id: "e".to_string(),
                sequence: 7,
                payload_format,
                payload: vec![1, 2],
                payload_schema: "s".to_string(),
            }],
        }
    }

    fn assert_exact_schema<const N: usize>(
        schema: &str,
        expected: [&str; N],
    ) -> Result<(), String> {
        let lines = schema
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        if lines != expected {
            return Err(format!(
                "schema mismatch\nexpected:\n{}\nactual:\n{}",
                expected.join("\n"),
                lines.join("\n")
            ));
        }
        Ok(())
    }

    fn demo_event() -> EventEnvelope {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/usr/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 80,
        };
        let flow = FlowContext {
            id: FlowIdentity::stable(&process, &local, &remote, TransportProtocol::Tcp, 1, None),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 100,
        };
        EventEnvelope::from_flow(
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            flow,
            CaptureOrigin::from_source(CaptureSource::Replay),
            "test",
            EventKind::HttpRequestHeaders(HttpHeaders {
                direction: Direction::Outbound,
                stream_sequence: 1,
                method: Some("GET".to_string()),
                target: Some("/".to_string()),
                status: None,
                reason: None,
                version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
            }),
        )
    }
}
