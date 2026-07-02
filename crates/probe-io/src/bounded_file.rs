use std::{
    fs::{self, File, Metadata},
    io::Read,
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};

use rustix::fs::{Mode, OFlags, ResolveFlags, open, openat2};
use thiserror::Error;

use crate::AllowedFileRoots;

#[derive(Debug, Error)]
pub enum BoundedFileError {
    #[error("bounded file path does not exist: {path}")]
    NotFound { path: PathBuf },
    #[error("failed to inspect bounded file {path}: {source}")]
    Inspect {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to open bounded file {path}: {source}")]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to read bounded file {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("bounded file path is a symlink: {path}")]
    Symlink { path: PathBuf },
    #[error("bounded file path is a directory: {path}")]
    Directory { path: PathBuf },
    #[error("bounded file path is not a regular file: {path}")]
    NotRegular { path: PathBuf },
    #[error("bounded file {path} is too large: {size} bytes exceeds {limit} bytes")]
    TooLarge {
        path: PathBuf,
        size: u64,
        limit: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundedFileErrorKind {
    NotFound,
    Inspect,
    Open,
    Read,
    Symlink,
    Directory,
    NotRegular,
    TooLarge,
}

#[derive(Debug, Error)]
pub enum RootedBoundedFileError {
    #[error(transparent)]
    Bounded(#[from] BoundedFileError),
    #[error("bounded file path must be absolute when filesystem roots are configured: {path}")]
    RelativePathDisallowed { path: PathBuf },
    #[error("bounded file path is outside configured filesystem roots: {path}")]
    OutsideAllowedRoots { path: PathBuf },
    #[error("failed to open bounded file root {root} for {path}: {source}")]
    OpenRoot {
        path: PathBuf,
        root: PathBuf,
        source: std::io::Error,
    },
}

#[derive(Debug, Error)]
pub enum OwnerPrivateFileError {
    #[error("file owner uid {owner_uid} does not match effective uid {effective_uid}")]
    OwnerMismatch { owner_uid: u32, effective_uid: u32 },
    #[error("file owner read bit is not set; permissions are {mode:o}")]
    OwnerUnreadable { mode: u32 },
    #[error("file has group/other permissions {mode:o}")]
    InsecurePermissions { mode: u32 },
}

#[derive(Debug, Error)]
pub enum PublicReadableFileError {
    #[error("file has no read permission bits set; permissions are {mode:o}")]
    Unreadable { mode: u32 },
    #[error("file is writable by group/other users; permissions are {mode:o}")]
    WritableByGroupOrOthers { mode: u32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundedFileSizeLimit {
    pub size: u64,
    pub limit: u64,
}

#[derive(Debug)]
pub struct BoundedFileErrorParts {
    pub kind: BoundedFileErrorKind,
    pub path: PathBuf,
    source: Option<std::io::Error>,
    size_limit: Option<BoundedFileSizeLimit>,
}

impl BoundedFileError {
    pub fn kind(&self) -> BoundedFileErrorKind {
        match self {
            Self::NotFound { .. } => BoundedFileErrorKind::NotFound,
            Self::Inspect { .. } => BoundedFileErrorKind::Inspect,
            Self::Open { .. } => BoundedFileErrorKind::Open,
            Self::Read { .. } => BoundedFileErrorKind::Read,
            Self::Symlink { .. } => BoundedFileErrorKind::Symlink,
            Self::Directory { .. } => BoundedFileErrorKind::Directory,
            Self::NotRegular { .. } => BoundedFileErrorKind::NotRegular,
            Self::TooLarge { .. } => BoundedFileErrorKind::TooLarge,
        }
    }

    pub fn path(&self) -> &Path {
        match self {
            Self::NotFound { path }
            | Self::Inspect { path, .. }
            | Self::Open { path, .. }
            | Self::Read { path, .. }
            | Self::Symlink { path }
            | Self::Directory { path }
            | Self::NotRegular { path }
            | Self::TooLarge { path, .. } => path,
        }
    }

    pub fn source(&self) -> Option<&std::io::Error> {
        match self {
            Self::Inspect { source, .. }
            | Self::Open { source, .. }
            | Self::Read { source, .. } => Some(source),
            Self::NotFound { .. }
            | Self::Symlink { .. }
            | Self::Directory { .. }
            | Self::NotRegular { .. }
            | Self::TooLarge { .. } => None,
        }
    }

    pub fn size_limit(&self) -> Option<BoundedFileSizeLimit> {
        match self {
            Self::TooLarge { size, limit, .. } => Some(BoundedFileSizeLimit {
                size: *size,
                limit: *limit,
            }),
            Self::NotFound { .. }
            | Self::Inspect { .. }
            | Self::Open { .. }
            | Self::Read { .. }
            | Self::Symlink { .. }
            | Self::Directory { .. }
            | Self::NotRegular { .. } => None,
        }
    }

    pub fn into_parts(self) -> BoundedFileErrorParts {
        match self {
            Self::NotFound { path } => {
                BoundedFileErrorParts::new(BoundedFileErrorKind::NotFound, path, None, None)
            }
            Self::Inspect { path, source } => {
                BoundedFileErrorParts::new(BoundedFileErrorKind::Inspect, path, Some(source), None)
            }
            Self::Open { path, source } => {
                BoundedFileErrorParts::new(BoundedFileErrorKind::Open, path, Some(source), None)
            }
            Self::Read { path, source } => {
                BoundedFileErrorParts::new(BoundedFileErrorKind::Read, path, Some(source), None)
            }
            Self::Symlink { path } => {
                BoundedFileErrorParts::new(BoundedFileErrorKind::Symlink, path, None, None)
            }
            Self::Directory { path } => {
                BoundedFileErrorParts::new(BoundedFileErrorKind::Directory, path, None, None)
            }
            Self::NotRegular { path } => {
                BoundedFileErrorParts::new(BoundedFileErrorKind::NotRegular, path, None, None)
            }
            Self::TooLarge { path, size, limit } => BoundedFileErrorParts::new(
                BoundedFileErrorKind::TooLarge,
                path,
                None,
                Some(BoundedFileSizeLimit { size, limit }),
            ),
        }
    }
}

impl BoundedFileErrorParts {
    fn new(
        kind: BoundedFileErrorKind,
        path: PathBuf,
        source: Option<std::io::Error>,
        size_limit: Option<BoundedFileSizeLimit>,
    ) -> Self {
        Self {
            kind,
            path,
            source,
            size_limit,
        }
    }

    pub fn take_source(&mut self) -> Option<std::io::Error> {
        self.source.take()
    }

    pub fn expect_source(&mut self) -> std::io::Error {
        self.take_source()
            .expect("bounded file error kind must include an I/O source")
    }

    pub fn size_limit(&self) -> Option<BoundedFileSizeLimit> {
        self.size_limit
    }

    pub fn expect_size_limit(&self) -> BoundedFileSizeLimit {
        self.size_limit
            .expect("bounded file error kind must include a size limit")
    }
}

#[derive(Debug)]
pub struct BoundedRegularFile {
    path: PathBuf,
    limit: u64,
    file: File,
    metadata: Metadata,
}

impl BoundedRegularFile {
    fn from_opened(
        path: impl Into<PathBuf>,
        limit: u64,
        file: File,
    ) -> Result<Self, BoundedFileError> {
        let path = path.into();
        let metadata = file
            .metadata()
            .map_err(|source| BoundedFileError::Inspect {
                path: path.clone(),
                source,
            })?;
        validate_regular_file(&path, limit, &metadata)?;
        Ok(Self {
            path,
            limit,
            file,
            metadata,
        })
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }

    pub fn read(self) -> Result<BoundedRegularFileRead, BoundedFileError> {
        let bytes = read_limited_bytes(&self.path, self.limit, self.file)?;
        validate_read_size(&self.path, self.limit, bytes.len() as u64)?;
        Ok(BoundedRegularFileRead {
            bytes,
            metadata: self.metadata,
        })
    }
}

#[derive(Debug)]
pub struct BoundedRegularFileRead {
    bytes: Vec<u8>,
    metadata: Metadata,
}

impl BoundedRegularFileRead {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn metadata(&self) -> &Metadata {
        &self.metadata
    }
}

pub fn check_bounded_regular_file(path: &Path, limit: u64) -> Result<(), BoundedFileError> {
    inspect_bounded_regular_file(path, limit).map(|_| ())
}

pub fn inspect_bounded_regular_file(path: &Path, limit: u64) -> Result<Metadata, BoundedFileError> {
    let metadata = symlink_safe_metadata(path)?;
    validate_regular_file(path, limit, &metadata)?;
    Ok(metadata)
}

pub fn read_bounded_regular_file(
    path: &Path,
    limit: u64,
) -> Result<BoundedRegularFileRead, BoundedFileError> {
    open_bounded_regular_file(path, limit)?.read()
}

pub fn open_bounded_regular_file_under_roots(
    path: &Path,
    allowed_roots: &AllowedFileRoots,
    limit: u64,
) -> Result<BoundedRegularFile, RootedBoundedFileError> {
    if allowed_roots.is_empty() {
        return open_bounded_regular_file(path, limit).map_err(RootedBoundedFileError::from);
    }
    if !path.is_absolute() {
        return Err(RootedBoundedFileError::RelativePathDisallowed {
            path: path.to_path_buf(),
        });
    }
    let (root, relative) = allowed_roots.root_for(path).ok_or_else(|| {
        RootedBoundedFileError::OutsideAllowedRoots {
            path: path.to_path_buf(),
        }
    })?;
    open_bounded_regular_file_under_root(path, root, relative, limit)
}

pub fn check_bounded_regular_file_under_root(
    root: &Path,
    relative: &Path,
    limit: u64,
) -> Result<(), RootedBoundedFileError> {
    reject_absolute_root_relative_path(relative)?;
    open_bounded_regular_file_under_root(&root.join(relative), root, relative, limit).map(|_| ())
}

pub fn read_bounded_regular_file_to_string_under_root(
    root: &Path,
    relative: &Path,
    limit: u64,
) -> Result<String, RootedBoundedFileError> {
    reject_absolute_root_relative_path(relative)?;
    let path = root.join(relative);
    let read = open_bounded_regular_file_under_root(&path, root, relative, limit)?.read()?;
    String::from_utf8(read.into_bytes()).map_err(|source| {
        RootedBoundedFileError::Bounded(BoundedFileError::Read {
            path,
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        })
    })
}

fn reject_absolute_root_relative_path(relative: &Path) -> Result<(), RootedBoundedFileError> {
    if relative.is_absolute() {
        return Err(RootedBoundedFileError::RelativePathDisallowed {
            path: relative.to_path_buf(),
        });
    }
    Ok(())
}

pub fn read_bounded_regular_file_to_string(
    path: &Path,
    limit: u64,
) -> Result<String, BoundedFileError> {
    let read = read_bounded_regular_file(path, limit)?;
    String::from_utf8(read.into_bytes()).map_err(|source| BoundedFileError::Read {
        path: path.to_path_buf(),
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
    })
}

pub fn open_bounded_regular_file(
    path: &Path,
    limit: u64,
) -> Result<BoundedRegularFile, BoundedFileError> {
    check_bounded_regular_file(path, limit)?;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| BoundedFileError::Open {
        path: path.to_path_buf(),
        source: source.into(),
    })?;
    let file = File::from(fd);
    BoundedRegularFile::from_opened(path.to_path_buf(), limit, file)
}

fn open_bounded_regular_file_under_root(
    path: &Path,
    root: &Path,
    relative: &Path,
    limit: u64,
) -> Result<BoundedRegularFile, RootedBoundedFileError> {
    let root_fd = open(
        root,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| RootedBoundedFileError::OpenRoot {
        path: path.to_path_buf(),
        root: root.to_path_buf(),
        source: source.into(),
    })?;
    let file_fd = openat2(
        &root_fd,
        relative,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|source| {
        if source == rustix::io::Errno::LOOP {
            return RootedBoundedFileError::Bounded(BoundedFileError::Symlink {
                path: path.to_path_buf(),
            });
        }
        if source == rustix::io::Errno::NOENT {
            return RootedBoundedFileError::Bounded(BoundedFileError::NotFound {
                path: path.to_path_buf(),
            });
        }
        let source = std::io::Error::from(source);
        RootedBoundedFileError::Bounded(BoundedFileError::Open {
            path: path.to_path_buf(),
            source,
        })
    })?;
    BoundedRegularFile::from_opened(path.to_path_buf(), limit, File::from(file_fd))
        .map_err(RootedBoundedFileError::from)
}

fn read_limited_bytes(path: &Path, limit: u64, file: File) -> Result<Vec<u8>, BoundedFileError> {
    let max_size = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut reader = file.take(limit.saturating_add(1));
    let mut bytes = Vec::new();
    let mut buffer = [0_u8; 8192];

    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|source| BoundedFileError::Read {
                path: path.to_path_buf(),
                source,
            })?;
        if read == 0 {
            break;
        }
        if bytes.len().saturating_add(read) > max_size {
            return Err(BoundedFileError::TooLarge {
                path: path.to_path_buf(),
                size: limit.saturating_add(1),
                limit,
            });
        }
        bytes
            .try_reserve(read)
            .map_err(|_| BoundedFileError::TooLarge {
                path: path.to_path_buf(),
                size: limit.saturating_add(1),
                limit,
            })?;
        bytes.extend_from_slice(&buffer[..read]);
    }
    Ok(bytes)
}

fn symlink_safe_metadata(path: &Path) -> Result<Metadata, BoundedFileError> {
    fs::symlink_metadata(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::NotFound {
            BoundedFileError::NotFound {
                path: path.to_path_buf(),
            }
        } else {
            BoundedFileError::Inspect {
                path: path.to_path_buf(),
                source,
            }
        }
    })
}

fn validate_regular_file(
    path: &Path,
    limit: u64,
    metadata: &Metadata,
) -> Result<(), BoundedFileError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(BoundedFileError::Symlink {
            path: path.to_path_buf(),
        });
    }
    if metadata.is_dir() {
        return Err(BoundedFileError::Directory {
            path: path.to_path_buf(),
        });
    }
    if !metadata.is_file() {
        return Err(BoundedFileError::NotRegular {
            path: path.to_path_buf(),
        });
    }
    validate_read_size(path, limit, metadata.len())
}

fn validate_read_size(path: &Path, limit: u64, size: u64) -> Result<(), BoundedFileError> {
    if size > limit {
        Err(BoundedFileError::TooLarge {
            path: path.to_path_buf(),
            size,
            limit,
        })
    } else {
        Ok(())
    }
}

pub fn validate_owner_private_file(metadata: &Metadata) -> Result<(), OwnerPrivateFileError> {
    let mode = metadata.permissions().mode() & 0o777;
    let effective_uid = rustix::process::geteuid().as_raw();
    let owner_uid = metadata.uid();
    if owner_uid != effective_uid {
        return Err(OwnerPrivateFileError::OwnerMismatch {
            owner_uid,
            effective_uid,
        });
    }
    if mode & 0o400 == 0 {
        return Err(OwnerPrivateFileError::OwnerUnreadable { mode });
    }
    if mode & 0o077 != 0 {
        return Err(OwnerPrivateFileError::InsecurePermissions { mode });
    }
    Ok(())
}

pub fn validate_public_readable_file(metadata: &Metadata) -> Result<(), PublicReadableFileError> {
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o444 == 0 {
        return Err(PublicReadableFileError::Unreadable { mode });
    }
    if mode & 0o022 != 0 {
        return Err(PublicReadableFileError::WritableByGroupOrOthers { mode });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn bounded_regular_file_reader_returns_bytes_and_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let path = temp.path().join("input.txt");
        fs::write(&path, b"hello")?;

        let read = read_bounded_regular_file(&path, 64)?;

        assert_eq!(read.bytes(), b"hello");
        assert_eq!(read.metadata().len(), 5);
        Ok(())
    }

    #[test]
    fn bounded_regular_file_inspector_returns_metadata() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let path = temp.path().join("input.txt");
        fs::write(&path, b"hello")?;

        let metadata = inspect_bounded_regular_file(&path, 64)?;

        assert_eq!(metadata.len(), 5);
        Ok(())
    }

    #[test]
    fn bounded_regular_file_reader_rejects_oversized_file() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let path = temp.path().join("input.txt");
        fs::write(&path, b"abcd")?;

        let error =
            read_bounded_regular_file(&path, 3).expect_err("oversized file must be rejected");

        assert_eq!(error.kind(), BoundedFileErrorKind::TooLarge);
        Ok(())
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn bounded_regular_file_reader_rejects_symlink() -> Result<(), Box<dyn std::error::Error>> {
        use std::os::unix::fs::symlink;

        let temp = tempdir()?;
        let target = temp.path().join("target.txt");
        let link = temp.path().join("link.txt");
        fs::write(&target, b"hello")?;
        symlink(&target, &link)?;

        let error =
            read_bounded_regular_file(&link, 64).expect_err("symlinked file must be rejected");

        assert_eq!(error.kind(), BoundedFileErrorKind::Symlink);
        Ok(())
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn root_bounded_reader_rejects_intermediate_symlink() -> Result<(), Box<dyn std::error::Error>>
    {
        use std::os::unix::fs::symlink;

        let temp = tempdir()?;
        let root = temp.path().join("root");
        let external = temp.path().join("external");
        fs::create_dir_all(&root)?;
        fs::create_dir_all(external.join("guard"))?;
        fs::write(external.join("guard").join("matcher.lua"), b"return {}")?;
        symlink(external.join("guard"), root.join("guard"))?;

        let error = read_bounded_regular_file_to_string_under_root(
            &root,
            Path::new("guard/matcher.lua"),
            64,
        )
        .expect_err("root-bound reader must reject intermediate symlinks");

        assert!(matches!(
            error,
            RootedBoundedFileError::Bounded(BoundedFileError::Symlink { .. })
        ));
        Ok(())
    }

    #[test]
    fn root_bounded_reader_rejects_absolute_relative_path() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let root = temp.path().join("root");
        fs::create_dir(&root)?;

        let error =
            read_bounded_regular_file_to_string_under_root(&root, Path::new("/etc/passwd"), 64)
                .expect_err("root-bound reader must reject absolute relative paths");

        assert!(matches!(
            error,
            RootedBoundedFileError::RelativePathDisallowed { .. }
        ));
        Ok(())
    }

    #[test]
    fn root_bounded_open_preserves_missing_target_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let temp = tempdir()?;
        let root = temp.path().join("root");
        fs::create_dir(&root)?;
        let missing = root.join("missing.pem");

        let roots = AllowedFileRoots::new(vec![root])?;
        let error = open_bounded_regular_file_under_roots(&missing, &roots, 64)
            .expect_err("missing target under allowed root must stay NotFound");

        assert!(matches!(
            error,
            RootedBoundedFileError::Bounded(BoundedFileError::NotFound { .. })
        ));
        Ok(())
    }

    #[test]
    fn public_readable_validation_rejects_missing_read_bits()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let path = temp.path().join("public.pem");
        fs::write(&path, b"certificate")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o200))?;

        let error = validate_public_readable_file(&fs::metadata(&path)?)
            .expect_err("public material must have at least one read bit");

        assert!(matches!(
            error,
            PublicReadableFileError::Unreadable { mode } if mode == 0o200
        ));
        Ok(())
    }

    #[test]
    fn public_readable_validation_rejects_group_or_other_writable_file()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempdir()?;
        let path = temp.path().join("public.pem");
        fs::write(&path, b"certificate")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666))?;

        let error = validate_public_readable_file(&fs::metadata(&path)?)
            .expect_err("public material must not be writable by group or others");

        assert!(matches!(
            error,
            PublicReadableFileError::WritableByGroupOrOthers { mode } if mode == 0o666
        ));
        Ok(())
    }
}
