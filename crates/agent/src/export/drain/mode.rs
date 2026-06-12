use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SinkDrainMode {
    UntilEmpty,
    MaxBatches {
        max_batches: u64,
        sink_timeout: Duration,
    },
}

impl SinkDrainMode {
    pub(super) fn can_continue_after(self, batches: u64) -> bool {
        match self {
            Self::UntilEmpty => true,
            Self::MaxBatches { max_batches, .. } => batches < max_batches,
        }
    }

    pub(super) fn sink_timeout(self) -> Option<Duration> {
        match self {
            Self::UntilEmpty => None,
            Self::MaxBatches { sink_timeout, .. } => Some(sink_timeout),
        }
    }
}

pub(super) fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
