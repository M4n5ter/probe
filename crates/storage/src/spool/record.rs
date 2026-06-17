use bytes::Bytes;
use probe_core::SpoolPayloadSchema;

use super::error::StorageError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpoolPayload {
    schema: SpoolPayloadSchema,
    bytes: Bytes,
}

impl SpoolPayload {
    pub fn new(schema: SpoolPayloadSchema, bytes: impl AsRef<[u8]>) -> Self {
        Self {
            schema,
            bytes: Bytes::copy_from_slice(bytes.as_ref()),
        }
    }

    pub fn schema(&self) -> &SpoolPayloadSchema {
        &self.schema
    }

    pub fn schema_wire(&self) -> &str {
        self.schema.as_str()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredEvent {
    pub sequence: u64,
    pub stored_at_unix_ns: u64,
    pub payload: SpoolPayload,
}

/// Result of an idempotent export append.
///
/// `Duplicate` means the dedup key already points to a retained, durable export
/// record. It is not a permanent tombstone: pruning or retention can make the key
/// appendable again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppendOutcome {
    Appended(StoredEvent),
    Duplicate { sequence: u64 },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RetentionPrune {
    pub pruned_count: u64,
    pub retired_through: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct SpoolRecord {
    pub stored_at_unix_ns: u64,
    pub payload: SpoolPayload,
}

pub(super) fn encode_spool_record(
    stored_at_unix_ns: u64,
    payload: &SpoolPayload,
) -> Result<Vec<u8>, StorageError> {
    let schema = payload.schema.as_str().as_bytes();
    let schema_len = u32::try_from(schema.len())
        .map_err(|_| StorageError::PayloadSchemaTooLarge { len: schema.len() })?;
    let mut encoded = Vec::with_capacity(12 + schema.len() + payload.bytes.len());
    encoded.extend_from_slice(&stored_at_unix_ns.to_be_bytes());
    encoded.extend_from_slice(&schema_len.to_be_bytes());
    encoded.extend_from_slice(schema);
    encoded.extend_from_slice(&payload.bytes);
    Ok(encoded)
}

pub(super) fn decode_spool_record(bytes: &[u8]) -> Result<SpoolRecord, StorageError> {
    if bytes.len() < 12 {
        return Err(StorageError::InvalidStoredRecord { len: bytes.len() });
    }
    let mut stored_at = [0_u8; 8];
    stored_at.copy_from_slice(&bytes[..8]);
    let mut len = [0_u8; 4];
    len.copy_from_slice(&bytes[8..12]);
    let schema_len = u32::from_be_bytes(len) as usize;
    let expected_min_len = 12 + schema_len;
    if bytes.len() < expected_min_len {
        return Err(StorageError::InvalidStoredRecord { len: bytes.len() });
    }
    let schema = String::from_utf8(bytes[12..expected_min_len].to_vec())?;
    let schema = SpoolPayloadSchema::from_wire(schema)?;
    Ok(SpoolRecord {
        stored_at_unix_ns: u64::from_be_bytes(stored_at),
        payload: SpoolPayload {
            schema,
            bytes: Bytes::copy_from_slice(&bytes[expected_min_len..]),
        },
    })
}

#[cfg(test)]
mod tests {
    use probe_core::SpoolPayloadSchema;

    use super::*;

    #[test]
    fn stored_record_decodes_known_wire_schema_to_canonical_enum()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut encoded = Vec::new();
        let schema = SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON.as_bytes();
        encoded.extend_from_slice(&42_u64.to_be_bytes());
        encoded.extend_from_slice(&(schema.len() as u32).to_be_bytes());
        encoded.extend_from_slice(schema);
        encoded.extend_from_slice(b"payload");

        let record = decode_spool_record(&encoded)?;

        assert_eq!(record.stored_at_unix_ns, 42);
        assert_eq!(
            record.payload.schema(),
            &SpoolPayloadSchema::EventEnvelopeSubjectOriginJson
        );
        assert_eq!(
            record.payload.schema_wire(),
            SpoolPayloadSchema::EVENT_ENVELOPE_SUBJECT_ORIGIN_JSON
        );
        assert_eq!(record.payload.bytes(), b"payload");
        Ok(())
    }

    #[test]
    fn stored_record_rejects_unknown_schema() -> Result<(), Box<dyn std::error::Error>> {
        let mut encoded = Vec::new();
        let schema = b"test.schema";
        encoded.extend_from_slice(&42_u64.to_be_bytes());
        encoded.extend_from_slice(&(schema.len() as u32).to_be_bytes());
        encoded.extend_from_slice(schema);
        encoded.extend_from_slice(b"payload");

        let error = decode_spool_record(&encoded).expect_err("unknown schema must fail");

        assert!(matches!(error, StorageError::InvalidStoredRecordSchema(_)));
        Ok(())
    }
}
