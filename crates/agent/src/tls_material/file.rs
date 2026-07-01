use std::{
    fs::Metadata,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use probe_io::{
    BoundedFileError, BoundedFileErrorKind, inspect_bounded_regular_file, open_bounded_regular_file,
};
use rustix::process::geteuid;

use super::{TlsMaterialFileStore, TlsMaterialFileStoreError};

pub(crate) const MAX_TLS_MATERIAL_BYTES: u64 = 1024 * 1024;
const INSECURE_TLS_MATERIAL_PERMISSION_BITS: u32 = 0o077;
const REQUIRED_OWNER_READ_BIT: u32 = 0o400;

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct FilesystemTlsMaterialStore;

impl TlsMaterialFileStore for FilesystemTlsMaterialStore {
    fn inspect_tls_material(&self, path: &Path) -> Result<(), TlsMaterialFileStoreError> {
        let metadata = inspect_bounded_regular_file(path, MAX_TLS_MATERIAL_BYTES)
            .map_err(tls_material_file_store_error)?;
        validate_tls_material_permissions(&metadata)
    }

    fn read_tls_material(&self, path: &Path) -> Result<Vec<u8>, TlsMaterialFileStoreError> {
        let file = open_bounded_regular_file(path, MAX_TLS_MATERIAL_BYTES)
            .map_err(tls_material_file_store_error)?;
        validate_tls_material_permissions(file.metadata())?;
        file.read()
            .map(|read| read.into_bytes())
            .map_err(tls_material_file_store_error)
    }
}

fn validate_tls_material_permissions(metadata: &Metadata) -> Result<(), TlsMaterialFileStoreError> {
    let mode = metadata.permissions().mode() & 0o777;
    let effective_uid = geteuid().as_raw();
    let owner_uid = metadata.uid();
    if owner_uid != effective_uid {
        return Err(TlsMaterialFileStoreError::OwnerMismatch {
            owner_uid,
            effective_uid,
        });
    }
    if mode & REQUIRED_OWNER_READ_BIT == 0 {
        return Err(TlsMaterialFileStoreError::OwnerUnreadable { mode });
    }
    if mode & INSECURE_TLS_MATERIAL_PERMISSION_BITS != 0 {
        return Err(TlsMaterialFileStoreError::InsecurePermissions { mode });
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use super::*;

    #[test]
    fn filesystem_store_accepts_owner_private_material() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("material.pem");
        fs::write(&path, b"material")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

        FilesystemTlsMaterialStore.inspect_tls_material(&path)?;
        assert_eq!(
            FilesystemTlsMaterialStore.read_tls_material(&path)?,
            b"material"
        );
        Ok(())
    }

    #[test]
    fn filesystem_store_rejects_group_or_other_accessible_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("material.pem");
        fs::write(&path, b"material")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;

        let error = FilesystemTlsMaterialStore
            .inspect_tls_material(&path)
            .expect_err("group-readable material must be rejected");

        assert!(matches!(
            error,
            TlsMaterialFileStoreError::InsecurePermissions { mode } if mode == 0o640
        ));

        let error = FilesystemTlsMaterialStore
            .read_tls_material(&path)
            .expect_err("group-readable material must not be read");

        assert!(matches!(
            error,
            TlsMaterialFileStoreError::InsecurePermissions { mode } if mode == 0o640
        ));
        Ok(())
    }

    #[test]
    fn filesystem_store_rejects_owner_unreadable_material() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("material.pem");
        fs::write(&path, b"material")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o200))?;

        let error = FilesystemTlsMaterialStore
            .inspect_tls_material(&path)
            .expect_err("owner-unreadable material must be rejected");

        assert!(matches!(
            error,
            TlsMaterialFileStoreError::OwnerUnreadable { mode } if mode == 0o200
        ));
        Ok(())
    }
}
