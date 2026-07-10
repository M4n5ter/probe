use std::{fmt, fs::File, path::Path};

use evidence::SegmentId;
use secure_io::{PrivateDirectory, PrivateDirectoryError};

const METADATA_FILE: &str = "metadata.redb";
const SEGMENTS_DIRECTORY: &str = "segments";

pub(crate) struct StoreLayout {
    root: PrivateDirectory,
    segments: PrivateDirectory,
}

impl StoreLayout {
    pub(crate) fn ensure(path: &Path) -> Result<Self, StoreLayoutError> {
        let root = PrivateDirectory::ensure(path).map_err(StoreLayoutError::Filesystem)?;
        let segments = root
            .ensure_dir(Path::new(SEGMENTS_DIRECTORY))
            .map_err(StoreLayoutError::Filesystem)?;
        Ok(Self { root, segments })
    }

    pub(crate) fn open_or_create_metadata(&self) -> Result<File, StoreLayoutError> {
        match self.root.create_new_file(Path::new(METADATA_FILE)) {
            Ok(file) => {
                self.root.sync().map_err(StoreLayoutError::Filesystem)?;
                Ok(file)
            }
            Err(PrivateDirectoryError::AlreadyExists { .. }) => self
                .root
                .open_file_read_write(Path::new(METADATA_FILE))
                .map_err(StoreLayoutError::Filesystem),
            Err(error) => Err(StoreLayoutError::Filesystem(error)),
        }
    }

    pub(crate) fn create_segment(&self, segment: SegmentId) -> Result<File, StoreLayoutError> {
        let name = segment_name(segment);
        let file = self
            .segments
            .create_new_file(Path::new(&name))
            .map_err(StoreLayoutError::Filesystem)?;
        self.segments.sync().map_err(StoreLayoutError::Filesystem)?;
        Ok(file)
    }

    pub(crate) fn open_or_create_segment_owner(
        &self,
        segment: SegmentId,
    ) -> Result<File, StoreLayoutError> {
        let name = segment_owner_name(segment);
        match self.segments.create_new_file(Path::new(&name)) {
            Ok(file) => {
                self.segments.sync().map_err(StoreLayoutError::Filesystem)?;
                Ok(file)
            }
            Err(PrivateDirectoryError::AlreadyExists { .. }) => self
                .segments
                .open_file_read_write(Path::new(&name))
                .map_err(StoreLayoutError::Filesystem),
            Err(error) => Err(StoreLayoutError::Filesystem(error)),
        }
    }

    pub(crate) fn open_segment_owner(&self, segment: SegmentId) -> Result<File, StoreLayoutError> {
        self.segments
            .open_file_read_write(Path::new(&segment_owner_name(segment)))
            .map_err(StoreLayoutError::Filesystem)
    }

    pub(crate) fn create_chunk_journal(&self) -> Result<File, StoreLayoutError> {
        self.segments
            .create_anonymous_file()
            .map_err(StoreLayoutError::Filesystem)
    }

    pub(crate) fn open_segment_read(&self, segment: SegmentId) -> Result<File, StoreLayoutError> {
        self.segments
            .open_file_read(Path::new(&segment_name(segment)))
            .map_err(StoreLayoutError::Filesystem)
    }

    pub(crate) fn open_segment_read_write(
        &self,
        segment: SegmentId,
    ) -> Result<File, StoreLayoutError> {
        self.segments
            .open_file_read_write(Path::new(&segment_name(segment)))
            .map_err(StoreLayoutError::Filesystem)
    }
}

#[derive(Debug)]
pub enum StoreLayoutError {
    Filesystem(PrivateDirectoryError),
}

impl fmt::Display for StoreLayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Filesystem(error) => {
                write!(formatter, "store filesystem boundary failed: {error}")
            }
        }
    }
}

impl std::error::Error for StoreLayoutError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Filesystem(error) => Some(error),
        }
    }
}

fn segment_name(segment: SegmentId) -> String {
    format!("{:032x}.segment", segment.get())
}

fn segment_owner_name(segment: SegmentId) -> String {
    format!("{:032x}.owner", segment.get())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn creates_owner_private_store_files_through_contained_handles() {
        let temp = tempdir().expect("temporary directory");
        let path = temp.path().join("store");
        let layout = StoreLayout::ensure(&path).expect("store layout");
        layout.open_or_create_metadata().expect("metadata file");
        let segment = SegmentId::new(0x42).expect("segment ID");
        layout.create_segment(segment).expect("segment file");
        layout
            .open_or_create_segment_owner(segment)
            .expect("segment owner file");

        assert_eq!(
            std::fs::metadata(path.join(METADATA_FILE))
                .expect("metadata mode")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(
                path.join(SEGMENTS_DIRECTORY)
                    .join(segment_owner_name(segment))
            )
            .expect("segment owner mode")
            .permissions()
            .mode()
                & 0o777,
            0o600
        );
        layout
            .open_or_create_segment_owner(segment)
            .expect("reopen segment owner file");
        assert_eq!(
            std::fs::metadata(path.join(SEGMENTS_DIRECTORY).join(segment_name(segment)))
                .expect("segment mode")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(matches!(
            layout.create_segment(segment),
            Err(StoreLayoutError::Filesystem(
                PrivateDirectoryError::AlreadyExists { .. }
            ))
        ));
    }
}
