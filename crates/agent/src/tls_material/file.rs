use std::path::Path;

use probe_io::{
    BoundedFileError, BoundedFileErrorKind, check_bounded_regular_file, read_bounded_regular_file,
};

use super::{TlsMaterialFileStore, TlsMaterialFileStoreError};

pub(crate) const MAX_TLS_MATERIAL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FilesystemTlsMaterialStore;

impl TlsMaterialFileStore for FilesystemTlsMaterialStore {
    fn inspect_tls_material(&self, path: &Path) -> Result<(), TlsMaterialFileStoreError> {
        check_bounded_regular_file(path, MAX_TLS_MATERIAL_BYTES)
            .map_err(tls_material_file_store_error)
    }

    fn read_tls_material(&self, path: &Path) -> Result<Vec<u8>, TlsMaterialFileStoreError> {
        read_bounded_regular_file(path, MAX_TLS_MATERIAL_BYTES)
            .map(|read| read.into_bytes())
            .map_err(tls_material_file_store_error)
    }
}

fn tls_material_file_store_error(error: BoundedFileError) -> TlsMaterialFileStoreError {
    let mut parts = error.into_parts();
    match parts.kind {
        BoundedFileErrorKind::NotFound => TlsMaterialFileStoreError::NotFound,
        BoundedFileErrorKind::Inspect => TlsMaterialFileStoreError::Inspect {
            source: parts.expect_source(),
        },
        BoundedFileErrorKind::Open => TlsMaterialFileStoreError::Open {
            source: parts.expect_source(),
        },
        BoundedFileErrorKind::Read => TlsMaterialFileStoreError::Read {
            source: parts.expect_source(),
        },
        BoundedFileErrorKind::Symlink => TlsMaterialFileStoreError::Symlink,
        BoundedFileErrorKind::Directory => TlsMaterialFileStoreError::Directory,
        BoundedFileErrorKind::NotRegular => TlsMaterialFileStoreError::NotRegular,
        BoundedFileErrorKind::TooLarge => {
            let size_limit = parts.expect_size_limit();
            TlsMaterialFileStoreError::TooLarge {
                size: size_limit.size,
                limit: size_limit.limit,
            }
        }
    }
}
