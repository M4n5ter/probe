use std::{fs, io::ErrorKind, path::Path};

use super::StorageError;

pub(super) const SPOOL_MARKER_FILE: &str = "traffic-probe-spool-format";
pub(super) const SPOOL_MARKER_CONTENT: &[u8] = b"traffic-probe-spool\n";
pub(super) const SPOOL_READY_FILE: &str = "traffic-probe-spool-ready";
const SPOOL_READY_CONTENT: &[u8] = b"ready\n";

pub(super) fn ensure_spool_markers(path: &Path) -> Result<(), StorageError> {
    ensure_marker_file(path, SPOOL_MARKER_FILE, SPOOL_MARKER_CONTENT)?;
    ensure_marker_file(path, SPOOL_READY_FILE, SPOOL_READY_CONTENT)?;
    Ok(())
}

pub(super) fn validate_existing_spool_markers(path: &Path) -> Result<(), StorageError> {
    read_spool_marker(path)?;
    read_spool_ready_marker(path)?;
    Ok(())
}

pub(super) fn read_spool_marker(path: &Path) -> Result<bool, StorageError> {
    read_marker_file(path, SPOOL_MARKER_FILE, SPOOL_MARKER_CONTENT)
}

pub(super) fn read_spool_ready_marker(path: &Path) -> Result<bool, StorageError> {
    read_marker_file(path, SPOOL_READY_FILE, SPOOL_READY_CONTENT)
}

fn ensure_marker_file(path: &Path, name: &str, content: &[u8]) -> Result<(), StorageError> {
    if read_marker_file(path, name, content)? {
        return Ok(());
    }
    fs::write(path.join(name), content)?;
    Ok(())
}

fn read_marker_file(path: &Path, name: &str, content: &[u8]) -> Result<bool, StorageError> {
    let marker_path = path.join(name);
    match fs::read(&marker_path) {
        Ok(existing_content) if existing_content == content => Ok(true),
        Ok(_) => Err(StorageError::InvalidSpoolMarker {
            path: marker_path.display().to_string(),
        }),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
