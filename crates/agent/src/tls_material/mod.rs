use std::{
    fs::{self, File, Metadata},
    io::Read,
    path::Path,
};

use rustix::fs::{Mode, OFlags, open};
use thiserror::Error;

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
    let metadata = fs::symlink_metadata(path).map_err(inspect_error)?;
    validate_regular_material(&metadata)
}

pub(crate) fn read_tls_material(path: &Path) -> Result<Vec<u8>, TlsMaterialFileError> {
    let file = open_regular_material(path)?;
    let metadata = file
        .metadata()
        .map_err(|source| TlsMaterialFileError::Inspect { source })?;
    validate_regular_material(&metadata)?;
    read_bounded_material(file)
}

fn open_regular_material(path: &Path) -> Result<File, TlsMaterialFileError> {
    check_tls_material_source(path)?;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| TlsMaterialFileError::Open {
        source: source.into(),
    })?;
    Ok(File::from(fd))
}

fn read_bounded_material(file: File) -> Result<Vec<u8>, TlsMaterialFileError> {
    let mut reader = file.take(MAX_TLS_MATERIAL_BYTES.saturating_add(1));
    let mut bytes = Vec::new();
    reader
        .read_to_end(&mut bytes)
        .map_err(|source| TlsMaterialFileError::Read { source })?;
    let size = bytes.len() as u64;
    if size > MAX_TLS_MATERIAL_BYTES {
        return Err(TlsMaterialFileError::TooLarge {
            size,
            limit: MAX_TLS_MATERIAL_BYTES,
        });
    }
    Ok(bytes)
}

fn validate_regular_material(metadata: &Metadata) -> Result<(), TlsMaterialFileError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(TlsMaterialFileError::Symlink);
    }
    if metadata.is_dir() {
        return Err(TlsMaterialFileError::Directory);
    }
    if !metadata.is_file() {
        return Err(TlsMaterialFileError::NotRegular);
    }
    if metadata.len() > MAX_TLS_MATERIAL_BYTES {
        return Err(TlsMaterialFileError::TooLarge {
            size: metadata.len(),
            limit: MAX_TLS_MATERIAL_BYTES,
        });
    }
    Ok(())
}

fn inspect_error(source: std::io::Error) -> TlsMaterialFileError {
    if source.kind() == std::io::ErrorKind::NotFound {
        TlsMaterialFileError::NotFound
    } else {
        TlsMaterialFileError::Inspect { source }
    }
}
