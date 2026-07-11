use std::{
    fmt,
    fs::{File, TryLockError},
    io,
    num::NonZeroU64,
    os::unix::fs::FileExt,
    path::Path,
};

use secure_io::{PrivateDirectory, PrivateDirectoryError, preallocate};

pub struct DurableDirectory {
    directory: PrivateDirectory,
}

impl DurableDirectory {
    pub fn ensure(path: &Path) -> Result<Self, DurableFileError> {
        PrivateDirectory::ensure(path)
            .map(|directory| Self { directory })
            .map_err(DurableFileError::Filesystem)
    }

    pub fn open_or_create_preallocated(
        &self,
        relative: &Path,
        capacity: NonZeroU64,
    ) -> Result<PreallocatedFile, DurableFileError> {
        let (file, created) = match self.directory.create_new_file(relative) {
            Ok(file) => (file, true),
            Err(PrivateDirectoryError::AlreadyExists { .. }) => (
                self.directory
                    .open_file_read_write(relative)
                    .map_err(DurableFileError::Filesystem)?,
                false,
            ),
            Err(error) => return Err(DurableFileError::Filesystem(error)),
        };
        lock_exclusive(&file)?;
        let actual = file.metadata().map_err(DurableFileError::Inspect)?.len();
        if actual != 0 && actual != capacity.get() {
            return Err(DurableFileError::CapacityMismatch {
                expected: capacity.get(),
                actual,
            });
        }
        preallocate(&file, capacity.get()).map_err(DurableFileError::Preallocate)?;
        file.sync_all().map_err(DurableFileError::Sync)?;
        if created || actual == 0 {
            self.directory
                .sync()
                .map_err(DurableFileError::Filesystem)?;
        }
        Ok(PreallocatedFile {
            file,
            capacity,
            created,
        })
    }
}

pub struct PreallocatedFile {
    file: File,
    capacity: NonZeroU64,
    created: bool,
}

impl PreallocatedFile {
    pub const fn capacity(&self) -> u64 {
        self.capacity.get()
    }

    pub const fn was_created(&self) -> bool {
        self.created
    }

    pub fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<(), DurableFileError> {
        self.ensure_range(offset, output.len())?;
        let mut read = 0;
        while read < output.len() {
            let position = offset
                .checked_add(read as u64)
                .ok_or(DurableFileError::RangeOverflow)?;
            match self.file.read_at(&mut output[read..], position) {
                Ok(0) => {
                    return Err(DurableFileError::UnexpectedEof {
                        offset,
                        expected: output.len(),
                        actual: read,
                    });
                }
                Ok(count) => read += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(source) => {
                    return Err(DurableFileError::Read {
                        offset,
                        read,
                        source,
                    });
                }
            }
        }
        Ok(())
    }

    pub fn write_all_at(&self, offset: u64, input: &[u8]) -> Result<(), DurableFileError> {
        self.ensure_range(offset, input.len())?;
        let mut written = 0;
        while written < input.len() {
            let position = offset
                .checked_add(written as u64)
                .ok_or(DurableFileError::RangeOverflow)?;
            match self.file.write_at(&input[written..], position) {
                Ok(0) => {
                    return Err(DurableFileError::WriteZero { offset, written });
                }
                Ok(count) => written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(source) => {
                    return Err(DurableFileError::Write {
                        offset,
                        written,
                        source,
                    });
                }
            }
        }
        Ok(())
    }

    pub fn sync_data(&self) -> Result<(), DurableFileError> {
        self.file.sync_data().map_err(DurableFileError::Sync)
    }

    pub fn sync_all(&self) -> Result<(), DurableFileError> {
        self.file.sync_all().map_err(DurableFileError::Sync)
    }

    fn ensure_range(&self, offset: u64, length: usize) -> Result<(), DurableFileError> {
        let length = u64::try_from(length).map_err(|_| DurableFileError::RangeOverflow)?;
        let end = offset
            .checked_add(length)
            .ok_or(DurableFileError::RangeOverflow)?;
        if end > self.capacity.get() {
            Err(DurableFileError::OutOfBounds {
                offset,
                length,
                capacity: self.capacity.get(),
            })
        } else {
            Ok(())
        }
    }
}

#[derive(Debug)]
pub enum DurableFileError {
    Filesystem(PrivateDirectoryError),
    Busy,
    Lock(io::Error),
    Inspect(io::Error),
    Preallocate(io::Error),
    CapacityMismatch {
        expected: u64,
        actual: u64,
    },
    OutOfBounds {
        offset: u64,
        length: u64,
        capacity: u64,
    },
    RangeOverflow,
    UnexpectedEof {
        offset: u64,
        expected: usize,
        actual: usize,
    },
    Read {
        offset: u64,
        read: usize,
        source: io::Error,
    },
    WriteZero {
        offset: u64,
        written: usize,
    },
    Write {
        offset: u64,
        written: usize,
        source: io::Error,
    },
    Sync(io::Error),
}

impl fmt::Display for DurableFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filesystem(error) => write!(formatter, "durable path boundary failed: {error}"),
            Self::Busy => formatter.write_str("durable file already has an active owner"),
            Self::Lock(error) => write!(
                formatter,
                "failed to acquire durable file ownership: {error}"
            ),
            Self::Inspect(error) => write!(formatter, "failed to inspect durable file: {error}"),
            Self::Preallocate(error) => {
                write!(formatter, "failed to preallocate durable file: {error}")
            }
            Self::CapacityMismatch { expected, actual } => write!(
                formatter,
                "durable file capacity is {actual} bytes, expected {expected}"
            ),
            Self::OutOfBounds {
                offset,
                length,
                capacity,
            } => write!(
                formatter,
                "durable file range {offset}+{length} exceeds capacity {capacity}"
            ),
            Self::RangeOverflow => formatter.write_str("durable file range overflows"),
            Self::UnexpectedEof {
                offset,
                expected,
                actual,
            } => write!(
                formatter,
                "durable file read at {offset} returned {actual} of {expected} bytes"
            ),
            Self::Read {
                offset,
                read,
                source,
            } => write!(
                formatter,
                "durable file read at {offset} failed after {read} bytes: {source}"
            ),
            Self::WriteZero { offset, written } => write!(
                formatter,
                "durable file write at {offset} made no progress after {written} bytes"
            ),
            Self::Write {
                offset,
                written,
                source,
            } => write!(
                formatter,
                "durable file write at {offset} failed after {written} bytes: {source}"
            ),
            Self::Sync(error) => write!(formatter, "failed to synchronize durable file: {error}"),
        }
    }
}

impl std::error::Error for DurableFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Filesystem(error) => Some(error),
            Self::Lock(error)
            | Self::Inspect(error)
            | Self::Preallocate(error)
            | Self::Sync(error) => Some(error),
            Self::Read { source, .. } | Self::Write { source, .. } => Some(source),
            Self::Busy
            | Self::CapacityMismatch { .. }
            | Self::OutOfBounds { .. }
            | Self::RangeOverflow
            | Self::UnexpectedEof { .. }
            | Self::WriteZero { .. } => None,
        }
    }
}

fn lock_exclusive(file: &File) -> Result<(), DurableFileError> {
    file.try_lock().map_err(|error| match error {
        TryLockError::WouldBlock => DurableFileError::Busy,
        TryLockError::Error(error) => DurableFileError::Lock(error),
    })
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn preallocated_file_is_exclusive_fixed_capacity_positioned_storage() {
        let temp = tempdir().expect("temporary durable directory");
        let root = temp.path().join("durable");
        let directory = DurableDirectory::ensure(&root).expect("durable directory");
        let capacity = NonZeroU64::new(1024 * 1024).expect("capacity");
        let file = directory
            .open_or_create_preallocated(Path::new("journal"), capacity)
            .expect("preallocated file");
        assert!(file.was_created());

        file.write_all_at(4096, b"prepared action")
            .expect("positioned write");
        file.sync_data().expect("durable write");
        let mut loaded = [0_u8; 15];
        file.read_exact_at(4096, &mut loaded)
            .expect("positioned read");
        assert_eq!(&loaded, b"prepared action");
        assert!(matches!(
            directory.open_or_create_preallocated(Path::new("journal"), capacity),
            Err(DurableFileError::Busy)
        ));
        assert!(matches!(
            file.write_all_at(capacity.get() - 1, &[1, 2]),
            Err(DurableFileError::OutOfBounds { .. })
        ));

        let metadata = std::fs::metadata(root.join("journal")).expect("journal metadata");
        assert_eq!(metadata.len(), capacity.get());
        assert!(metadata.blocks() * 512 >= capacity.get());
    }

    #[test]
    fn existing_preallocated_file_rejects_a_different_capacity() {
        let temp = tempdir().expect("temporary durable directory");
        let directory =
            DurableDirectory::ensure(&temp.path().join("durable")).expect("durable directory");
        let first = directory
            .open_or_create_preallocated(
                Path::new("journal"),
                NonZeroU64::new(4096).expect("capacity"),
            )
            .expect("preallocated file");
        drop(first);

        assert!(matches!(
            directory.open_or_create_preallocated(
                Path::new("journal"),
                NonZeroU64::new(8192).expect("capacity"),
            ),
            Err(DurableFileError::CapacityMismatch {
                expected: 8192,
                actual: 4096
            })
        ));
    }

    #[test]
    fn existing_sparse_file_is_fully_reserved_before_use() {
        let temp = tempdir().expect("temporary durable directory");
        let root = temp.path().join("durable");
        let directory = DurableDirectory::ensure(&root).expect("durable directory");
        let capacity = NonZeroU64::new(1024 * 1024).expect("capacity");
        let sparse = directory
            .directory
            .create_new_file(Path::new("journal"))
            .expect("sparse journal");
        sparse.set_len(capacity.get()).expect("sparse length");
        sparse.sync_all().expect("sparse metadata");
        drop(sparse);

        let file = directory
            .open_or_create_preallocated(Path::new("journal"), capacity)
            .expect("re-reserved journal");
        assert!(!file.was_created());
        let metadata = std::fs::metadata(root.join("journal")).expect("journal metadata");
        assert!(metadata.blocks() * 512 >= capacity.get());
    }
}
