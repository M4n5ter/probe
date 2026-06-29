use std::{
    fs::{File, OpenOptions},
    io::Write,
    path::Path,
    sync::Mutex,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use capture::{CaptureEvent, PlaintextChunk, PlaintextConnection, PlaintextEvent, PlaintextSource};
use probe_core::{Direction, FlowContext, Timestamp};

use crate::{MitmProxyError, error::io_error};

pub(crate) struct CaptureEventFeedWriter {
    file: Mutex<File>,
    started: Instant,
}

impl CaptureEventFeedWriter {
    pub(crate) fn create(path: &Path) -> Result<Self, MitmProxyError> {
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .map_err(io_error("create MITM plaintext bridge feed"))?;
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
    use probe_core::Direction;

    use super::*;

    #[test]
    fn flow_offsets_are_tracked_per_direction() {
        let mut offsets = FlowOffsets::default();

        assert_eq!(offsets.record(Direction::Outbound, 5), 0);
        assert_eq!(offsets.record(Direction::Outbound, 3), 5);
        assert_eq!(offsets.record(Direction::Inbound, 7), 0);
        assert_eq!(offsets.record(Direction::Inbound, 2), 7);
    }
}
