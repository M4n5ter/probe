use std::{
    fs::{self, File, Metadata},
    io::Read,
    path::{Path, PathBuf},
};

use rustix::fs::{Mode, OFlags, open};
use thiserror::Error;

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
    let metadata = file
        .metadata()
        .map_err(|source| BoundedFileError::Inspect {
            path: path.to_path_buf(),
            source,
        })?;
    validate_regular_file(path, limit, &metadata)?;
    Ok(BoundedRegularFile {
        path: path.to_path_buf(),
        limit,
        file,
        metadata,
    })
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

#[cfg(test)]
mod tests {
    use std::fs;

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
}
