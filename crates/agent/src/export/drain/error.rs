use std::path::PathBuf;

use probe_config::{ExporterTransport, TlsMaterialKind};
use thiserror::Error;

use crate::tls_material::TlsMaterialFileError;

#[derive(Debug, Error)]
pub enum ExportDrainError {
    #[error("storage error: {0}")]
    Storage(#[from] storage::StorageError),
    #[error("proto error: {0}")]
    Proto(#[from] proto::ProtoError),
    #[error("export error: {0}")]
    Export(#[from] exporter::ExportError),
    #[error("{transport:?} exporter is reserved but not implemented")]
    UnsupportedTransport { transport: ExporterTransport },
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
        source: TlsMaterialFileError,
    },
    #[error("client TLS identity requires at least one client certificate and one private key")]
    IncompleteClientTlsIdentity,
}
