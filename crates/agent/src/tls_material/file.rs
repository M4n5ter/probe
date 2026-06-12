use std::path::Path;

use thiserror::Error;

use probe_io::{
    BoundedFileError, BoundedFileErrorKind, check_bounded_regular_file, read_bounded_regular_file,
};

pub(crate) const MAX_TLS_MATERIAL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Error)]
pub(crate) enum TlsMaterialFileError {
    #[error("TLS material path does not exist")]
    NotFound,
    #[error("failed to inspect TLS material: {source}")]
    Inspect { source: std::io::Error },
    #[error("failed to open TLS material: {source}")]
    Open { source: std::io::Error },
    #[error("failed to read TLS material: {source}")]
    Read { source: std::io::Error },
    #[error("TLS material path is a symlink")]
    Symlink,
    #[error("TLS material path is a directory")]
    Directory,
    #[error("TLS material path is not a regular file")]
    NotRegular,
    #[error("TLS material is too large: {size} bytes exceeds {limit} bytes")]
    TooLarge { size: u64, limit: u64 },
}

pub(crate) fn check_tls_material_source(path: &Path) -> Result<(), TlsMaterialFileError> {
    check_bounded_regular_file(path, MAX_TLS_MATERIAL_BYTES).map_err(tls_material_file_error)
}

pub(crate) fn read_tls_material(path: &Path) -> Result<Vec<u8>, TlsMaterialFileError> {
    read_bounded_regular_file(path, MAX_TLS_MATERIAL_BYTES)
        .map(|read| read.into_bytes())
        .map_err(tls_material_file_error)
}

fn tls_material_file_error(error: BoundedFileError) -> TlsMaterialFileError {
    let mut parts = error.into_parts();
    match parts.kind {
        BoundedFileErrorKind::NotFound => TlsMaterialFileError::NotFound,
        BoundedFileErrorKind::Inspect => TlsMaterialFileError::Inspect {
            source: parts.expect_source(),
        },
        BoundedFileErrorKind::Open => TlsMaterialFileError::Open {
            source: parts.expect_source(),
        },
        BoundedFileErrorKind::Read => TlsMaterialFileError::Read {
            source: parts.expect_source(),
        },
        BoundedFileErrorKind::Symlink => TlsMaterialFileError::Symlink,
        BoundedFileErrorKind::Directory => TlsMaterialFileError::Directory,
        BoundedFileErrorKind::NotRegular => TlsMaterialFileError::NotRegular,
        BoundedFileErrorKind::TooLarge => {
            let size_limit = parts.expect_size_limit();
            TlsMaterialFileError::TooLarge {
                size: size_limit.size,
                limit: size_limit.limit,
            }
        }
    }
}
