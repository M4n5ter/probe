use std::path::PathBuf;

use probe_config::TlsMaterialKind;
use serde::Serialize;
use thiserror::Error;

use crate::tls_material::TlsMaterialFileStoreError;

#[derive(Debug, Error)]
pub enum ExportDrainError {
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),
    #[error("proto error: {0}")]
    Proto(#[from] proto::ProtoError),
    #[error("export error: {0}")]
    Export(#[from] exporter::ExportError),
    #[error("one or more exporters failed: {failures}")]
    MultipleSinksFailed { failures: String },
    #[error("unsupported spooled payload schema at sequence {sequence}: {schema}")]
    UnsupportedSpoolPayloadSchema { sequence: u64, schema: String },
    #[error("exporter sink {sink} timed out after {timeout_ms} ms")]
    SinkTimedOut { sink: String, timeout_ms: u64 },
    #[error("TLS material {id} ({kind:?}) at {path}: {source}")]
    TlsMaterial {
        id: String,
        kind: TlsMaterialKind,
        path: PathBuf,
        source: TlsMaterialFileStoreError,
    },
    #[error("client TLS identity requires at least one client certificate and one private key")]
    IncompleteClientTlsIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportDrainFailureReason {
    StorageError,
    ProtoError,
    CompressionError,
    HttpTransportError,
    InvalidExporterHeader,
    ReservedExporterHeader,
    EmptyTlsTrustAnchorBundle,
    RemoteRejectedBatch,
    InvalidExportAck,
    MultipleSinksFailed,
    UnsupportedPayloadSchema,
    SinkTimedOut,
    TlsMaterialUnavailable,
    IncompleteClientTlsIdentity,
}

impl ExportDrainError {
    pub(crate) fn runtime_failure_reason(&self) -> ExportDrainFailureReason {
        match self {
            Self::Storage(_) => ExportDrainFailureReason::StorageError,
            Self::Proto(_) => ExportDrainFailureReason::ProtoError,
            Self::Export(error) => export_error_failure_reason(error),
            Self::MultipleSinksFailed { .. } => ExportDrainFailureReason::MultipleSinksFailed,
            Self::UnsupportedSpoolPayloadSchema { .. } => {
                ExportDrainFailureReason::UnsupportedPayloadSchema
            }
            Self::SinkTimedOut { .. } => ExportDrainFailureReason::SinkTimedOut,
            Self::TlsMaterial { .. } => ExportDrainFailureReason::TlsMaterialUnavailable,
            Self::IncompleteClientTlsIdentity => {
                ExportDrainFailureReason::IncompleteClientTlsIdentity
            }
        }
    }
}

fn export_error_failure_reason(error: &exporter::ExportError) -> ExportDrainFailureReason {
    match error {
        exporter::ExportError::Compression(_) | exporter::ExportError::Zstd(_) => {
            ExportDrainFailureReason::CompressionError
        }
        exporter::ExportError::Http(_) => ExportDrainFailureReason::HttpTransportError,
        exporter::ExportError::InvalidHeaderName { .. }
        | exporter::ExportError::InvalidHeaderValue { .. } => {
            ExportDrainFailureReason::InvalidExporterHeader
        }
        exporter::ExportError::ReservedHeaderName { .. } => {
            ExportDrainFailureReason::ReservedExporterHeader
        }
        exporter::ExportError::EmptyTrustAnchorBundle => {
            ExportDrainFailureReason::EmptyTlsTrustAnchorBundle
        }
        exporter::ExportError::Rejected { .. } => ExportDrainFailureReason::RemoteRejectedBatch,
        exporter::ExportError::InvalidAckResponse { .. }
        | exporter::ExportError::AckBatchMismatch { .. }
        | exporter::ExportError::AckMissingCursor { .. }
        | exporter::ExportError::AckCursorOutOfRange { .. } => {
            ExportDrainFailureReason::InvalidExportAck
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_failure_reason_redacts_error_details() {
        let error = ExportDrainError::TlsMaterial {
            id: "client-key".to_string(),
            kind: TlsMaterialKind::ClientPrivateKey,
            path: PathBuf::from("/secret/client.key"),
            source: TlsMaterialFileStoreError::NotRegular,
        };

        assert_eq!(
            error.runtime_failure_reason(),
            ExportDrainFailureReason::TlsMaterialUnavailable
        );
    }

    #[test]
    fn runtime_failure_reason_groups_export_ack_errors() {
        let error = ExportDrainError::Export(exporter::ExportError::AckCursorOutOfRange {
            batch_id: "batch-1".to_string(),
            cursor: 10,
            min_sequence: 1,
            max_sequence: 2,
        });

        assert_eq!(
            error.runtime_failure_reason(),
            ExportDrainFailureReason::InvalidExportAck
        );
    }
}
