use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum TlsMaterialFileStoreError {
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

pub(crate) trait TlsMaterialFileStore {
    fn inspect_tls_material(&self, path: &Path) -> Result<(), TlsMaterialFileStoreError>;

    fn read_tls_material(&self, path: &Path) -> Result<Vec<u8>, TlsMaterialFileStoreError>;
}
