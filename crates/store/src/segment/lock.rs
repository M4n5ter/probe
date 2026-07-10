use std::{fmt, fs::File, fs::TryLockError, io};

#[derive(Debug)]
pub enum SegmentLockError {
    Busy,
    Io(io::Error),
}

impl fmt::Display for SegmentLockError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => formatter.write_str("segment already has an incompatible active owner"),
            Self::Io(error) => write!(formatter, "failed to acquire segment ownership: {error}"),
        }
    }
}

impl std::error::Error for SegmentLockError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Busy => None,
            Self::Io(error) => Some(error),
        }
    }
}

pub(crate) fn lock_exclusive(file: &File) -> Result<(), SegmentLockError> {
    file.try_lock().map_err(map_lock_error)
}

pub(crate) fn lock_shared(file: &File) -> Result<(), SegmentLockError> {
    file.try_lock_shared().map_err(map_lock_error)
}

fn map_lock_error(error: TryLockError) -> SegmentLockError {
    match error {
        TryLockError::WouldBlock => SegmentLockError::Busy,
        TryLockError::Error(error) => SegmentLockError::Io(error),
    }
}
