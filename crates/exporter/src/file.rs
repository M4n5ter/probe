use std::{
    ffi::OsStr,
    fs::{self, File},
    io::{ErrorKind, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Component, Path, PathBuf},
};

use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use bytes::Bytes;
use proto::BatchEnvelope;
use rustix::{
    fs::{Access, AtFlags, CWD, Mode, OFlags, accessat, open, openat},
    process::geteuid,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{BatchExporter, CompressionCodec, ExportAck, ExportError};

const PRIVATE_FILE_MODE: u32 = 0o600;
const INSECURE_PERMISSION_BITS: u32 = 0o077;

#[derive(Debug, Clone)]
pub struct FileExporter {
    path: PathBuf,
    codec: CompressionCodec,
}

impl FileExporter {
    pub fn new(path: impl Into<PathBuf>, codec: CompressionCodec) -> Self {
        Self {
            path: path.into(),
            codec,
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn preflight_path(path: impl AsRef<Path>) -> Result<(), ExportError> {
        preflight_file_path(path.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileBatchRecord {
    pub kind: FileBatchRecordKind,
    pub batch_id: String,
    pub agent_id: String,
    pub codec: CompressionCodec,
    pub first_sequence: u64,
    pub last_sequence: u64,
    pub event_count: usize,
    pub payload: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileBatchRecordKind {
    ProtobufBatch,
}

#[derive(Debug, Error)]
pub enum FileBatchRecordDecodeError {
    #[error("file batch record payload base64 decode failed: {0}")]
    Payload(#[from] base64::DecodeError),
    #[error("file batch record payload decompression failed: {0}")]
    Codec(#[from] ExportError),
}

impl FileBatchRecord {
    pub fn encoded_payload(&self) -> Result<Vec<u8>, base64::DecodeError> {
        STANDARD.decode(&self.payload)
    }

    pub fn decode_payload(&self) -> Result<Bytes, FileBatchRecordDecodeError> {
        let payload = self.encoded_payload()?;
        Ok(self.codec.decode(&payload)?)
    }
}

#[async_trait]
impl BatchExporter for FileExporter {
    async fn send_batch(&self, batch: &BatchEnvelope) -> Result<ExportAck, ExportError> {
        let first_sequence = batch
            .events
            .iter()
            .map(|event| event.sequence)
            .min()
            .ok_or_else(|| ExportError::EmptyBatch {
                batch_id: batch.batch_id.clone(),
            })?;
        let last_sequence = batch
            .events
            .iter()
            .map(|event| event.sequence)
            .max()
            .expect("non-empty batch has a max sequence");
        let encoded = batch.encode_to_vec();
        let payload = self.codec.encode(&encoded)?;
        let record = FileBatchRecord {
            kind: FileBatchRecordKind::ProtobufBatch,
            batch_id: batch.batch_id.clone(),
            agent_id: batch.agent_id.clone(),
            codec: self.codec,
            first_sequence,
            last_sequence,
            event_count: batch.events.len(),
            payload: STANDARD.encode(payload),
        };
        let mut line = serde_json::to_vec(&record).map_err(ExportError::FileRecord)?;
        line.push(b'\n');

        let path = self.path.clone();
        tokio::task::spawn_blocking(move || append_record_line(&path, &line))
            .await
            .map_err(ExportError::FileTask)??;

        Ok(ExportAck {
            batch_id: batch.batch_id.clone(),
            committed_cursor: last_sequence,
        })
    }
}

struct AppendFile {
    file: File,
    parent: Option<File>,
}

fn append_record_line(path: &Path, line: &[u8]) -> Result<(), ExportError> {
    let AppendFile { mut file, parent } = open_private_append_file(path)?;
    file.write_all(line).map_err(ExportError::File)?;
    file.flush().map_err(ExportError::File)?;
    file.sync_data().map_err(ExportError::File)?;
    if let Some(parent) = parent {
        sync_parent_directory(&parent)?;
    }
    Ok(())
}

fn open_private_append_file(path: &Path) -> Result<AppendFile, ExportError> {
    let _file_name = target_file_name(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            validate_path_metadata_with(path, metadata)?;
            open_existing_private_append_file(path)
        }
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            match create_private_append_file(path) {
                Ok(file) => Ok(file),
                Err(ExportError::File(error)) if error.kind() == ErrorKind::AlreadyExists => {
                    open_existing_private_append_file(path)
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(ExportError::File(error)),
    }
}

fn create_private_append_file(path: &Path) -> Result<AppendFile, ExportError> {
    let parent = open_parent_directory(path, ParentAccess::Create)?;
    let fd = openat(
        &parent,
        target_file_name(path)?,
        OFlags::WRONLY
            | OFlags::APPEND
            | OFlags::CREATE
            | OFlags::EXCL
            | OFlags::CLOEXEC
            | OFlags::NOFOLLOW,
        Mode::from_raw_mode(PRIVATE_FILE_MODE),
    )
    .map_err(|source| ExportError::File(source.into()))?;
    let file = File::from(fd);
    validate_open_file(path, &file)?;
    Ok(AppendFile {
        file,
        parent: Some(parent),
    })
}

fn open_existing_private_append_file(path: &Path) -> Result<AppendFile, ExportError> {
    let parent = open_parent_directory(path, ParentAccess::Lookup)?;
    let fd = openat(
        &parent,
        target_file_name(path)?,
        OFlags::WRONLY | OFlags::APPEND | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| ExportError::File(source.into()))?;
    let file = File::from(fd);
    validate_open_file(path, &file)?;
    Ok(AppendFile { file, parent: None })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParentAccess {
    Lookup,
    Create,
}

fn open_parent_directory(path: &Path, access: ParentAccess) -> Result<File, ExportError> {
    validate_parent_directory(path, access)?;
    let parent = parent_directory(path);
    let fd = open(
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|source| ExportError::FileParentUnavailable {
        path: path.to_path_buf(),
        parent: parent.to_path_buf(),
        source: source.into(),
    })?;
    Ok(File::from(fd))
}

fn validate_path_metadata_with(path: &Path, metadata: fs::Metadata) -> Result<(), ExportError> {
    let file_type = metadata.file_type();
    if file_type.is_symlink() {
        return Err(ExportError::FileSymlink {
            path: path.to_path_buf(),
        });
    }
    validate_regular_file(path, metadata.is_file())?;
    validate_private_owner(path, metadata.uid())?;
    validate_private_permissions(path, metadata.permissions().mode())?;
    validate_file_write_access(path)
}

fn preflight_file_path(path: &Path) -> Result<(), ExportError> {
    let _file_name = target_file_name(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => validate_path_metadata_with(path, metadata),
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            open_parent_directory(path, ParentAccess::Create).map(|_| ())
        }
        Err(error) => Err(ExportError::File(error)),
    }
}

fn validate_parent_directory(path: &Path, access: ParentAccess) -> Result<(), ExportError> {
    let parent = parent_directory(path);
    let metadata =
        fs::symlink_metadata(parent).map_err(|source| ExportError::FileParentUnavailable {
            path: path.to_path_buf(),
            parent: parent.to_path_buf(),
            source,
        })?;
    if metadata.file_type().is_symlink() {
        return Err(ExportError::FileParentSymlink {
            path: path.to_path_buf(),
            parent: parent.to_path_buf(),
        });
    }
    if metadata.is_dir() {
        if access == ParentAccess::Create {
            validate_parent_write_access(path, parent)?;
        }
        Ok(())
    } else {
        Err(ExportError::FileParentNotDirectory {
            path: path.to_path_buf(),
            parent: parent.to_path_buf(),
        })
    }
}

fn validate_open_file(path: &Path, file: &File) -> Result<(), ExportError> {
    let metadata = file.metadata().map_err(ExportError::File)?;
    validate_regular_file(path, metadata.is_file())?;
    validate_private_owner(path, metadata.uid())?;
    validate_private_permissions(path, metadata.permissions().mode())
}

fn validate_regular_file(path: &Path, is_file: bool) -> Result<(), ExportError> {
    if is_file {
        Ok(())
    } else {
        Err(ExportError::FileNotRegular {
            path: path.to_path_buf(),
        })
    }
}

fn validate_private_permissions(path: &Path, mode: u32) -> Result<(), ExportError> {
    let mode = mode & 0o777;
    if mode & INSECURE_PERMISSION_BITS == 0 {
        Ok(())
    } else {
        Err(ExportError::FileInsecurePermissions {
            path: path.to_path_buf(),
            mode,
        })
    }
}

fn validate_private_owner(path: &Path, owner_uid: u32) -> Result<(), ExportError> {
    validate_private_owner_with_effective_uid(path, owner_uid, geteuid().as_raw())
}

fn validate_private_owner_with_effective_uid(
    path: &Path,
    owner_uid: u32,
    effective_uid: u32,
) -> Result<(), ExportError> {
    if owner_uid == effective_uid {
        Ok(())
    } else {
        Err(ExportError::FileOwnerMismatch {
            path: path.to_path_buf(),
            owner_uid,
            effective_uid,
        })
    }
}

fn validate_file_write_access(path: &Path) -> Result<(), ExportError> {
    accessat(CWD, path, Access::WRITE_OK, AtFlags::EACCESS).map_err(|source| {
        ExportError::FileNotWritable {
            path: path.to_path_buf(),
            source: source.into(),
        }
    })
}

fn validate_parent_write_access(path: &Path, parent: &Path) -> Result<(), ExportError> {
    accessat(
        CWD,
        parent,
        Access::WRITE_OK | Access::EXEC_OK,
        AtFlags::EACCESS,
    )
    .map_err(|source| ExportError::FileParentNotWritable {
        path: path.to_path_buf(),
        parent: parent.to_path_buf(),
        source: source.into(),
    })
}

fn sync_parent_directory(parent: &File) -> Result<(), ExportError> {
    parent.sync_all().map_err(ExportError::File)
}

fn parent_directory(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

fn target_file_name(path: &Path) -> Result<&OsStr, ExportError> {
    match path.components().next_back() {
        Some(Component::Normal(file_name)) => Ok(file_name),
        _ => Err(ExportError::FileInvalidTargetName {
            path: path.to_path_buf(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use proto::BatchEnvelope;
    use rustix::{
        fs::chown,
        process::{Uid, geteuid},
    };

    use super::*;

    #[tokio::test]
    async fn file_exporter_appends_json_lines_after_compression()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("export.jsonl");
        let exporter = FileExporter::new(&path, CompressionCodec::Gzip);
        let batch = BatchEnvelope {
            batch_id: "batch-1".to_string(),
            agent_id: "agent-1".to_string(),
            codec: "gzip".to_string(),
            events: vec![proto::EventRecord {
                event_id: "event-1".to_string(),
                sequence: 7,
                payload_format: proto::PayloadFormat::Json as i32,
                payload: br#"{"id":"event-1"}"#.to_vec(),
                payload_schema: "sssa.probe.event_envelope.subject_origin.json".to_string(),
            }],
        };

        let ack = exporter.send_batch(&batch).await?;

        assert_eq!(ack.batch_id, "batch-1");
        assert_eq!(ack.committed_cursor, 7);
        let contents = std::fs::read_to_string(&path)?;
        let lines = contents.lines().collect::<Vec<_>>();
        assert_eq!(lines.len(), 1);
        let record = serde_json::from_str::<FileBatchRecord>(lines[0])?;
        assert_eq!(record.kind, FileBatchRecordKind::ProtobufBatch);
        assert_eq!(record.codec, CompressionCodec::Gzip);
        assert_eq!(record.first_sequence, 7);
        assert_eq!(record.last_sequence, 7);
        let decoded = record.decode_payload()?;
        assert_eq!(BatchEnvelope::decode_from_slice(&decoded)?, batch);
        Ok(())
    }

    #[tokio::test]
    async fn file_exporter_creates_private_files() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("export.jsonl");
        let exporter = FileExporter::new(&path, CompressionCodec::None);

        exporter.send_batch(&single_event_batch()).await?;

        let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
        assert_eq!(mode & INSECURE_PERMISSION_BITS, 0);
        Ok(())
    }

    #[tokio::test]
    async fn file_exporter_rejects_insecure_existing_files()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("export.jsonl");
        std::fs::write(&path, b"")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))?;
        let exporter = FileExporter::new(&path, CompressionCodec::None);

        let error = exporter
            .send_batch(&single_event_batch())
            .await
            .expect_err("insecure export files must be rejected");

        assert!(matches!(
            error,
            ExportError::FileInsecurePermissions { mode: 0o644, .. }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn file_exporter_rejects_symlink_targets() -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let target = temp.path().join("target.jsonl");
        let link = temp.path().join("export.jsonl");
        std::fs::write(&target, b"")?;
        std::os::unix::fs::symlink(&target, &link)?;
        let exporter = FileExporter::new(&link, CompressionCodec::None);

        let error = exporter
            .send_batch(&single_event_batch())
            .await
            .expect_err("symlink export files must be rejected");

        assert!(matches!(error, ExportError::FileSymlink { .. }));
        Ok(())
    }

    #[test]
    fn file_exporter_preflight_accepts_missing_file_with_existing_parent()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("export.jsonl");

        FileExporter::preflight_path(path)?;

        Ok(())
    }

    #[test]
    fn file_exporter_preflight_rejects_non_directory_parent()
    -> Result<(), Box<dyn std::error::Error>> {
        let temp = tempfile::tempdir()?;
        let parent = temp.path().join("not-a-directory");
        std::fs::write(&parent, b"")?;
        let path = parent.join("export.jsonl");

        let error = FileExporter::preflight_path(&path)
            .expect_err("file exporter parent must be a directory");

        assert!(matches!(error, ExportError::FileParentNotDirectory { .. }));
        Ok(())
    }

    #[test]
    fn file_exporter_preflight_rejects_unwritable_parent() -> Result<(), Box<dyn std::error::Error>>
    {
        if geteuid().is_root() {
            return Ok(());
        }
        let temp = tempfile::tempdir()?;
        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o500))?;
        let path = temp.path().join("export.jsonl");

        let error =
            FileExporter::preflight_path(&path).expect_err("file exporter parent must be writable");

        std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700))?;
        assert!(matches!(error, ExportError::FileParentNotWritable { .. }));
        Ok(())
    }

    #[test]
    fn file_exporter_rejects_existing_files_owned_by_another_uid() {
        let path = Path::new("/tmp/export.jsonl");

        let error = validate_private_owner_with_effective_uid(path, 1001, 1000)
            .expect_err("file exporter must reject files owned by another uid");

        assert!(matches!(
            error,
            ExportError::FileOwnerMismatch {
                owner_uid: 1001,
                effective_uid: 1000,
                ..
            }
        ));
    }

    #[test]
    fn file_exporter_preflight_rejects_existing_files_owned_by_another_uid()
    -> Result<(), Box<dyn std::error::Error>> {
        if !geteuid().is_root() {
            return Ok(());
        }
        let temp = tempfile::tempdir()?;
        let path = temp.path().join("export.jsonl");
        std::fs::write(&path, b"")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        chown(&path, Some(Uid::from_raw(1)), None)?;

        let error = FileExporter::preflight_path(&path)
            .expect_err("file exporter must reject files owned by another uid");

        assert!(matches!(
            error,
            ExportError::FileOwnerMismatch {
                owner_uid: 1,
                effective_uid: 0,
                ..
            }
        ));
        Ok(())
    }

    #[tokio::test]
    async fn file_exporter_rejects_empty_batches() {
        let exporter = FileExporter::new("/tmp/unused-export.jsonl", CompressionCodec::None);
        let batch = BatchEnvelope {
            batch_id: "empty".to_string(),
            agent_id: "agent-1".to_string(),
            codec: "none".to_string(),
            events: Vec::new(),
        };

        assert!(matches!(
            exporter.send_batch(&batch).await,
            Err(ExportError::EmptyBatch { batch_id }) if batch_id == "empty"
        ));
    }

    fn single_event_batch() -> BatchEnvelope {
        BatchEnvelope {
            batch_id: "batch-1".to_string(),
            agent_id: "agent-1".to_string(),
            codec: "none".to_string(),
            events: vec![proto::EventRecord {
                event_id: "event-1".to_string(),
                sequence: 1,
                payload_format: proto::PayloadFormat::Json as i32,
                payload: br#"{"id":"event-1"}"#.to_vec(),
                payload_schema: "sssa.probe.event_envelope.subject_origin.json".to_string(),
            }],
        }
    }
}
