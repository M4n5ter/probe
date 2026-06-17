use std::time::{SystemTime, UNIX_EPOCH};

use probe_core::Timestamp;

#[derive(Default)]
pub(super) struct EbpfObservationClock {
    monotonic_sequence: u64,
}

impl EbpfObservationClock {
    pub(super) fn next_timestamp(&mut self) -> Timestamp {
        self.monotonic_sequence = self.monotonic_sequence.saturating_add(1);
        Timestamp {
            monotonic_ns: self.monotonic_sequence,
            wall_time_unix_ns: current_wall_time_unix_ns(),
        }
    }
}

fn current_wall_time_unix_ns() -> i64 {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    nanos.min(i64::MAX as u128) as i64
}
