use std::path::Path;

use probe_config::TlsMaterialKind;
use probe_io::{
    AllowedFileRoots, BoundedFileError, BoundedFileErrorKind, BoundedRegularFile,
    OwnerPrivateFileError, PublicReadableFileError, RootedBoundedFileError,
    open_bounded_regular_file, open_bounded_regular_file_under_roots, validate_owner_private_file,
    validate_public_readable_file,
};
use runtime::TlsMaterialStorePlan;

use super::{
    TlsMaterialFileStore, TlsMaterialFileStoreError, store::tls_material_requires_private_file,
};

pub(crate) const MAX_TLS_MATERIAL_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, Default)]
pub(crate) struct FilesystemTlsMaterialStore {
    allowed_roots: AllowedFileRoots,
}

impl FilesystemTlsMaterialStore {
    pub(crate) fn from_plan(plan: &TlsMaterialStorePlan) -> Self {
        Self {
            allowed_roots: AllowedFileRoots::new(plan.allowed_roots().to_vec())
                .expect("runtime plan TLS material roots must be validated"),
        }
    }

    #[cfg(test)]
    fn with_allowed_roots(allowed_roots: Vec<std::path::PathBuf>) -> Self {
        Self {
            allowed_roots: AllowedFileRoots::new(allowed_roots)
                .expect("test TLS material roots must be valid"),
        }
    }

    fn open_tls_material(
        &self,
        path: &Path,
    ) -> Result<BoundedRegularFile, TlsMaterialFileStoreError> {
        open_bounded_regular_file_under_roots(path, &self.allowed_roots, MAX_TLS_MATERIAL_BYTES)
            .map_err(rooted_tls_material_file_store_error)
    }
}

impl TlsMaterialFileStore for FilesystemTlsMaterialStore {
    fn inspect_tls_material(
        &self,
        kind: TlsMaterialKind,
        path: &Path,
    ) -> Result<(), TlsMaterialFileStoreError> {
        if self.allowed_roots.is_empty() {
            let file = open_bounded_regular_file(path, MAX_TLS_MATERIAL_BYTES)
                .map_err(tls_material_file_store_error)?;
            return validate_tls_material_permissions(kind, file.metadata());
        }
        let file = self.open_tls_material(path)?;
        validate_tls_material_permissions(kind, file.metadata())
    }

    fn read_tls_material(
        &self,
        kind: TlsMaterialKind,
        path: &Path,
    ) -> Result<Vec<u8>, TlsMaterialFileStoreError> {
        let file = self.open_tls_material(path)?;
        validate_tls_material_permissions(kind, file.metadata())?;
        file.read()
            .map(|read| read.into_bytes())
            .map_err(tls_material_file_store_error)
    }
}

fn validate_tls_material_permissions(
    kind: TlsMaterialKind,
    metadata: &std::fs::Metadata,
) -> Result<(), TlsMaterialFileStoreError> {
    if tls_material_requires_private_file(kind) {
        return validate_owner_private_file(metadata).map_err(owner_private_file_error);
    }
    validate_public_readable_file(metadata).map_err(public_readable_file_error)
}

fn owner_private_file_error(error: OwnerPrivateFileError) -> TlsMaterialFileStoreError {
    match error {
        OwnerPrivateFileError::OwnerMismatch {
            owner_uid,
            effective_uid,
        } => TlsMaterialFileStoreError::OwnerMismatch {
            owner_uid,
            effective_uid,
        },
        OwnerPrivateFileError::OwnerUnreadable { mode } => {
            TlsMaterialFileStoreError::OwnerUnreadable { mode }
        }
        OwnerPrivateFileError::InsecurePermissions { mode } => {
            TlsMaterialFileStoreError::InsecurePermissions { mode }
        }
    }
}

fn public_readable_file_error(error: PublicReadableFileError) -> TlsMaterialFileStoreError {
    match error {
        PublicReadableFileError::Unreadable { mode } => {
            TlsMaterialFileStoreError::Unreadable { mode }
        }
        PublicReadableFileError::WritableByGroupOrOthers { mode } => {
            TlsMaterialFileStoreError::InsecurePermissions { mode }
        }
    }
}

fn rooted_tls_material_file_store_error(
    error: RootedBoundedFileError,
) -> TlsMaterialFileStoreError {
    match error {
        RootedBoundedFileError::Bounded(error) => tls_material_file_store_error(error),
        RootedBoundedFileError::RelativePathDisallowed { .. } => {
            TlsMaterialFileStoreError::RelativePathDisallowed
        }
        RootedBoundedFileError::OutsideAllowedRoots { .. } => {
            TlsMaterialFileStoreError::PathOutsideAllowedRoots
        }
        RootedBoundedFileError::OpenRoot { root, source, .. } => {
            TlsMaterialFileStoreError::OpenAllowedRoot { root, source }
        }
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

        let store = FilesystemTlsMaterialStore::default();
        store.inspect_tls_material(TlsMaterialKind::ClientPrivateKey, &path)?;
        assert_eq!(
            store.read_tls_material(TlsMaterialKind::ClientPrivateKey, &path)?,
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

        let store = FilesystemTlsMaterialStore::default();
        let error = store
            .inspect_tls_material(TlsMaterialKind::ClientPrivateKey, &path)
            .expect_err("group-readable material must be rejected");

        assert!(matches!(
            error,
            TlsMaterialFileStoreError::InsecurePermissions { mode } if mode == 0o640
        ));

        let error = store
            .read_tls_material(TlsMaterialKind::ClientPrivateKey, &path)
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

        let store = FilesystemTlsMaterialStore::default();
        let error = store
            .inspect_tls_material(TlsMaterialKind::ClientPrivateKey, &path)
            .expect_err("owner-unreadable material must be rejected");

        match error {
            TlsMaterialFileStoreError::Open { .. }
            | TlsMaterialFileStoreError::OwnerUnreadable { mode: 0o200 } => {}
            other => panic!("unexpected owner-unreadable material error: {other}"),
        }
        Ok(())
    }

    #[test]
    fn filesystem_store_accepts_material_beneath_allowed_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("materials");
        fs::create_dir(&root)?;
        let path = root.join("material.pem");
        fs::write(&path, b"material")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let store = FilesystemTlsMaterialStore::with_allowed_roots(vec![root]);

        store.inspect_tls_material(TlsMaterialKind::ClientPrivateKey, &path)?;
        assert_eq!(
            store.read_tls_material(TlsMaterialKind::ClientPrivateKey, &path)?,
            b"material"
        );
        Ok(())
    }

    #[test]
    fn filesystem_store_rejects_material_outside_allowed_roots()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("materials");
        let outside = temp.path().join("outside");
        fs::create_dir(&root)?;
        fs::create_dir(&outside)?;
        let path = outside.join("material.pem");
        fs::write(&path, b"material")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let store = FilesystemTlsMaterialStore::with_allowed_roots(vec![root]);

        let error = store
            .read_tls_material(TlsMaterialKind::ClientPrivateKey, &path)
            .expect_err("material outside allowed roots must be rejected");

        assert!(matches!(
            error,
            TlsMaterialFileStoreError::PathOutsideAllowedRoots
        ));
        Ok(())
    }

    #[test]
    fn filesystem_store_rejects_symlink_escape_beneath_allowed_root()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let root = temp.path().join("materials");
        let outside = temp.path().join("outside");
        fs::create_dir(&root)?;
        fs::create_dir(&outside)?;
        let path = outside.join("material.pem");
        fs::write(&path, b"material")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        std::os::unix::fs::symlink(&outside, root.join("escape"))?;
        let store = FilesystemTlsMaterialStore::with_allowed_roots(vec![root.clone()]);

        let error = store
            .read_tls_material(
                TlsMaterialKind::ClientPrivateKey,
                &root.join("escape").join("material.pem"),
            )
            .expect_err("symlink escape under allowed root must be rejected");

        assert!(matches!(error, TlsMaterialFileStoreError::Symlink));
        Ok(())
    }

    #[test]
    fn filesystem_store_accepts_group_readable_public_material()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("ca.pem");
        fs::write(&path, b"certificate")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))?;

        let store = FilesystemTlsMaterialStore::default();
        store.inspect_tls_material(TlsMaterialKind::TrustAnchor, &path)?;
        assert_eq!(
            store.read_tls_material(TlsMaterialKind::TrustAnchor, &path)?,
            b"certificate"
        );
        Ok(())
    }

    #[test]
    fn filesystem_store_rejects_public_material_writable_by_group_or_others()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("ca.pem");
        fs::write(&path, b"certificate")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;

        let store = FilesystemTlsMaterialStore::default();
        let error = store
            .inspect_tls_material(TlsMaterialKind::TrustAnchor, &path)
            .expect_err("writable public material must be rejected");

        assert!(matches!(
            error,
            TlsMaterialFileStoreError::InsecurePermissions { mode } if mode == 0o666
        ));
        Ok(())
    }

    #[test]
    fn filesystem_store_rejects_public_material_without_read_bits()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("ca.pem");
        fs::write(&path, b"certificate")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o200))?;

        let store = FilesystemTlsMaterialStore::default();
        let error = store
            .inspect_tls_material(TlsMaterialKind::TrustAnchor, &path)
            .expect_err("unreadable public material must be rejected");

        match error {
            TlsMaterialFileStoreError::Open { .. }
            | TlsMaterialFileStoreError::Unreadable { mode: 0o200 } => {}
            other => panic!("unexpected unreadable public material error: {other}"),
        }
        Ok(())
    }
}
