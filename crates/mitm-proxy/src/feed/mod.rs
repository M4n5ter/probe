use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use capture::{CaptureEvent, PlaintextChunk, PlaintextConnection, PlaintextEvent, PlaintextSource};
use probe_core::{Direction, FlowContext, Timestamp};
use rustix::fs::OFlags;

use crate::{MitmProxyError, error::io_error};

#[derive(Debug)]
pub(crate) struct CaptureEventFeedWriter {
    file: Mutex<File>,
    started: Instant,
}

impl CaptureEventFeedWriter {
    pub(crate) fn create(path: &Path) -> Result<Self, MitmProxyError> {
        ensure_feed_parent_directory(path)?;
        let file = open_feed_file(path)?;
        Ok(Self {
            file: Mutex::new(file),
            started: Instant::now(),
        })
    }

    pub(crate) fn connection_opened(&self, flow: &FlowContext) -> Result<(), MitmProxyError> {
        self.write_event(connection(
            PlaintextEvent::connection_opened,
            self.timestamp(),
            flow.clone(),
        ))
    }

    pub(crate) fn bytes(
        &self,
        flow: &FlowContext,
        direction: Direction,
        stream_offset: u64,
        bytes: &[u8],
    ) -> Result<(), MitmProxyError> {
        self.write_event(
            PlaintextEvent::bytes(
                PlaintextSource::L7MitmPlaintext,
                PlaintextChunk::new(self.timestamp(), flow.clone(), direction, bytes)
                    .with_stream_offset(stream_offset),
            )
            .into(),
        )
    }

    pub(crate) fn connection_closed(&self, flow: FlowContext) -> Result<(), MitmProxyError> {
        self.write_event(connection(
            PlaintextEvent::connection_closed,
            self.timestamp(),
            flow,
        ))
    }

    fn write_event(&self, event: CaptureEvent) -> Result<(), MitmProxyError> {
        let mut file = self
            .file
            .lock()
            .expect("capture event feed mutex should not be poisoned");
        serde_json::to_writer(&mut *file, &event)?;
        file.write_all(b"\n")
            .map_err(io_error("write MITM plaintext bridge feed newline"))?;
        file.flush()
            .map_err(io_error("flush MITM plaintext bridge feed"))
    }

    fn timestamp(&self) -> Timestamp {
        let wall_time_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX))
            .unwrap_or_default();
        Timestamp {
            monotonic_ns: u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX),
            wall_time_unix_ns,
        }
    }
}

fn open_feed_file(path: &Path) -> Result<File, MitmProxyError> {
    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .custom_flags(OFlags::NOFOLLOW.bits() as i32)
        .open(path)
        .map_err(io_error("create MITM plaintext bridge feed"))?;
    let metadata = file
        .metadata()
        .map_err(io_error("inspect MITM plaintext bridge feed"))?;
    if !metadata.is_file() {
        return Err(MitmProxyError::Io {
            action: "inspect MITM plaintext bridge feed",
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "feed path must be a real regular file",
            ),
        });
    }
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(io_error("secure MITM plaintext bridge feed permissions"))?;
    Ok(file)
}

fn ensure_feed_parent_directory(path: &Path) -> Result<(), MitmProxyError> {
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Ok(());
    };
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(MitmProxyError::Io {
                action: "prepare MITM plaintext bridge feed directory",
                source: std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "feed parent must be a real directory",
                ),
            })
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => fs::create_dir_all(parent)
            .and_then(|()| fs::set_permissions(parent, fs::Permissions::from_mode(0o700)))
            .map_err(io_error("prepare MITM plaintext bridge feed directory")),
        Err(source) => Err(io_error("prepare MITM plaintext bridge feed directory")(
            source,
        )),
    }
}

#[derive(Debug, Default)]
pub(crate) struct FlowOffsets {
    inbound: u64,
    outbound: u64,
}

impl FlowOffsets {
    pub(crate) fn record(&mut self, direction: Direction, len: usize) -> u64 {
        let offset = match direction {
            Direction::Inbound => &mut self.inbound,
            Direction::Outbound => &mut self.outbound,
        };
        let current = *offset;
        *offset = offset.saturating_add(u64::try_from(len).unwrap_or(u64::MAX));
        current
    }
}

fn connection(
    kind: fn(PlaintextSource, PlaintextConnection) -> PlaintextEvent,
    timestamp: Timestamp,
    flow: FlowContext,
) -> CaptureEvent {
    kind(
        PlaintextSource::L7MitmPlaintext,
        PlaintextConnection::new(timestamp, flow),
    )
    .into()
}

#[cfg(test)]
mod tests {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use probe_core::Direction;
    use tempfile::TempDir;

    use super::*;

    #[test]
    fn flow_offsets_are_tracked_per_direction() {
        let mut offsets = FlowOffsets::default();

        assert_eq!(offsets.record(Direction::Outbound, 5), 0);
        assert_eq!(offsets.record(Direction::Outbound, 3), 5);
        assert_eq!(offsets.record(Direction::Inbound, 7), 0);
        assert_eq!(offsets.record(Direction::Inbound, 2), 7);
    }

    #[test]
    fn feed_writer_creates_parent_directory() {
        let temp = TempDir::new().expect("temp dir");
        let feed_path = temp.path().join("mitm").join("feed.jsonl");

        let _writer = CaptureEventFeedWriter::create(&feed_path).expect("create feed writer");

        assert!(feed_path.is_file());
        assert_eq!(
            fs::metadata(feed_path.parent().expect("feed parent"))
                .expect("feed parent metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }

    #[test]
    fn feed_writer_uses_private_file_permissions() {
        let temp = TempDir::new().expect("temp dir");
        let feed_path = temp.path().join("feed.jsonl");

        let _writer = CaptureEventFeedWriter::create(&feed_path).expect("create feed writer");

        assert_eq!(
            fs::metadata(&feed_path)
                .expect("feed metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn feed_writer_reuses_existing_feed_file() {
        let temp = TempDir::new().expect("temp dir");
        let feed_path = temp.path().join("feed.jsonl");
        fs::write(&feed_path, "stale\n").expect("write stale feed");

        let _writer = CaptureEventFeedWriter::create(&feed_path).expect("create feed writer");

        assert_eq!(
            fs::read_to_string(&feed_path).expect("read feed after create"),
            ""
        );
        CaptureEventFeedWriter::create(&feed_path).expect("create feed writer again");
    }

    #[cfg(unix)]
    #[test]
    fn feed_writer_rejects_symlink_feed_path_without_truncating_target() {
        let temp = TempDir::new().expect("temp dir");
        let target_path = temp.path().join("target");
        let feed_path = temp.path().join("feed.jsonl");
        fs::write(&target_path, "do not truncate\n").expect("write target");
        symlink(&target_path, &feed_path).expect("create feed symlink");

        CaptureEventFeedWriter::create(&feed_path).expect_err("symlink feed must be rejected");

        assert_eq!(
            fs::read_to_string(&target_path).expect("read symlink target"),
            "do not truncate\n"
        );
    }
}
