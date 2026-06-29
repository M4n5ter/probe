use capture::{CaptureEvent, CapturedLoss};
use probe_core::{CaptureSource, Timestamp};
use serde::Serialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TlsPlaintextProviderActivityRuntimeSnapshot {
    pub progress_signals: u64,
    pub capture_events: u64,
    pub output_loss_events: u64,
    pub lost_events: u64,
    pub last_signal: Option<TlsPlaintextProviderSignalRuntimeSnapshot>,
}

impl TlsPlaintextProviderActivityRuntimeSnapshot {
    pub(super) fn record_progress(&mut self, observed_unix_ns: u64) {
        self.apply(TlsPlaintextProviderActivityUpdate {
            counter: TlsPlaintextProviderActivityCounter::Progress,
            signal: TlsPlaintextProviderSignalRuntimeSnapshot::Progress {
                sequence: self.next_sequence(),
                observed_unix_ns,
            },
        });
    }

    pub(super) fn record_event(&mut self, event: &CaptureEvent, observed_unix_ns: u64) -> bool {
        let Some(update) = self.update_from_capture_event(event, observed_unix_ns) else {
            return false;
        };
        self.apply(update);
        true
    }

    fn update_from_capture_event(
        &self,
        event: &CaptureEvent,
        observed_unix_ns: u64,
    ) -> Option<TlsPlaintextProviderActivityUpdate> {
        let sequence = self.next_sequence();
        match event {
            CaptureEvent::Bytes(bytes) if bytes.origin.source() == CaptureSource::LibsslUprobe => {
                Some(TlsPlaintextProviderActivityUpdate {
                    counter: TlsPlaintextProviderActivityCounter::CaptureEvent,
                    signal: TlsPlaintextProviderSignalRuntimeSnapshot::Bytes {
                        sequence,
                        observed_unix_ns,
                        capture_timestamp: bytes.timestamp,
                    },
                })
            }
            CaptureEvent::Gap(gap) if gap.origin.source() == CaptureSource::LibsslUprobe => {
                Some(TlsPlaintextProviderActivityUpdate {
                    counter: TlsPlaintextProviderActivityCounter::CaptureEvent,
                    signal: TlsPlaintextProviderSignalRuntimeSnapshot::Gap {
                        sequence,
                        observed_unix_ns,
                        capture_timestamp: gap.timestamp,
                    },
                })
            }
            CaptureEvent::ConnectionOpened {
                timestamp, origin, ..
            } if origin.source() == CaptureSource::LibsslUprobe => {
                Some(TlsPlaintextProviderActivityUpdate {
                    counter: TlsPlaintextProviderActivityCounter::CaptureEvent,
                    signal: TlsPlaintextProviderSignalRuntimeSnapshot::ConnectionOpened {
                        sequence,
                        observed_unix_ns,
                        capture_timestamp: *timestamp,
                    },
                })
            }
            CaptureEvent::ConnectionClosed {
                timestamp, origin, ..
            } if origin.source() == CaptureSource::LibsslUprobe => {
                Some(TlsPlaintextProviderActivityUpdate {
                    counter: TlsPlaintextProviderActivityCounter::CaptureEvent,
                    signal: TlsPlaintextProviderSignalRuntimeSnapshot::ConnectionClosed {
                        sequence,
                        observed_unix_ns,
                        capture_timestamp: *timestamp,
                    },
                })
            }
            CaptureEvent::Loss(loss) if loss.origin.source() == CaptureSource::LibsslUprobe => {
                Some(self.output_loss_update(loss, sequence, observed_unix_ns))
            }
            _ => None,
        }
    }

    fn output_loss_update(
        &self,
        loss: &CapturedLoss,
        sequence: u64,
        observed_unix_ns: u64,
    ) -> TlsPlaintextProviderActivityUpdate {
        TlsPlaintextProviderActivityUpdate {
            counter: TlsPlaintextProviderActivityCounter::OutputLoss {
                lost_events: loss.loss.lost_events,
            },
            signal: TlsPlaintextProviderSignalRuntimeSnapshot::OutputLoss {
                sequence,
                observed_unix_ns,
                capture_timestamp: loss.timestamp,
                lost_events: loss.loss.lost_events,
            },
        }
    }

    fn apply(&mut self, update: TlsPlaintextProviderActivityUpdate) {
        match update.counter {
            TlsPlaintextProviderActivityCounter::Progress => {
                self.progress_signals = self.progress_signals.saturating_add(1);
            }
            TlsPlaintextProviderActivityCounter::CaptureEvent => {
                self.capture_events = self.capture_events.saturating_add(1);
            }
            TlsPlaintextProviderActivityCounter::OutputLoss { lost_events } => {
                self.output_loss_events = self.output_loss_events.saturating_add(1);
                self.lost_events = self.lost_events.saturating_add(lost_events);
            }
        }
        self.last_signal = Some(update.signal);
    }

    fn next_sequence(&self) -> u64 {
        self.progress_signals
            .saturating_add(self.capture_events)
            .saturating_add(self.output_loss_events)
            .saturating_add(1)
    }
}

struct TlsPlaintextProviderActivityUpdate {
    counter: TlsPlaintextProviderActivityCounter,
    signal: TlsPlaintextProviderSignalRuntimeSnapshot,
}

enum TlsPlaintextProviderActivityCounter {
    Progress,
    CaptureEvent,
    OutputLoss { lost_events: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TlsPlaintextProviderSignalRuntimeSnapshot {
    Progress {
        sequence: u64,
        observed_unix_ns: u64,
    },
    Bytes {
        sequence: u64,
        observed_unix_ns: u64,
        capture_timestamp: Timestamp,
    },
    Gap {
        sequence: u64,
        observed_unix_ns: u64,
        capture_timestamp: Timestamp,
    },
    ConnectionOpened {
        sequence: u64,
        observed_unix_ns: u64,
        capture_timestamp: Timestamp,
    },
    ConnectionClosed {
        sequence: u64,
        observed_unix_ns: u64,
        capture_timestamp: Timestamp,
    },
    OutputLoss {
        sequence: u64,
        observed_unix_ns: u64,
        capture_timestamp: Timestamp,
        lost_events: u64,
    },
}

impl TlsPlaintextProviderSignalRuntimeSnapshot {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::Progress { .. } => "progress",
            Self::Bytes { .. } => "bytes",
            Self::Gap { .. } => "gap",
            Self::ConnectionOpened { .. } => "connection_opened",
            Self::ConnectionClosed { .. } => "connection_closed",
            Self::OutputLoss { .. } => "output_loss",
        }
    }

    pub(crate) fn sequence(&self) -> u64 {
        match self {
            Self::Progress { sequence, .. }
            | Self::Bytes { sequence, .. }
            | Self::Gap { sequence, .. }
            | Self::ConnectionOpened { sequence, .. }
            | Self::ConnectionClosed { sequence, .. }
            | Self::OutputLoss { sequence, .. } => *sequence,
        }
    }

    pub(crate) fn observed_unix_ns(&self) -> u64 {
        match self {
            Self::Progress {
                observed_unix_ns, ..
            }
            | Self::Bytes {
                observed_unix_ns, ..
            }
            | Self::Gap {
                observed_unix_ns, ..
            }
            | Self::ConnectionOpened {
                observed_unix_ns, ..
            }
            | Self::ConnectionClosed {
                observed_unix_ns, ..
            }
            | Self::OutputLoss {
                observed_unix_ns, ..
            } => *observed_unix_ns,
        }
    }
}

#[cfg(test)]
mod tests {
    use capture::{CaptureEvent, CapturedLoss};
    use probe_core::{CaptureLoss, CaptureOrigin, CaptureSource, EnforcementEvidence, Timestamp};

    use super::*;

    #[test]
    fn activity_records_progress_and_libssl_output_loss_without_cross_source_pollution() {
        let mut activity = TlsPlaintextProviderActivityRuntimeSnapshot::default();

        activity.record_progress(100);
        assert!(activity.record_event(
            &output_loss_event(CaptureSource::LibsslUprobe, timestamp(7), 3),
            200,
        ));
        assert!(!activity.record_event(
            &output_loss_event(CaptureSource::EbpfSyscall, timestamp(8), 5),
            300,
        ));

        assert_eq!(activity.progress_signals, 1);
        assert_eq!(activity.capture_events, 0);
        assert_eq!(activity.output_loss_events, 1);
        assert_eq!(activity.lost_events, 3);
        let signal = activity
            .last_signal
            .expect("last provider activity signal should be recorded");
        assert_eq!(signal.kind(), "output_loss");
        assert_eq!(signal.sequence(), 2);
        assert_eq!(signal.observed_unix_ns(), 200);
        let TlsPlaintextProviderSignalRuntimeSnapshot::OutputLoss {
            capture_timestamp,
            lost_events,
            ..
        } = signal
        else {
            panic!("expected output loss signal");
        };
        assert_eq!(capture_timestamp, timestamp(7));
        assert_eq!(lost_events, 3);
    }

    fn output_loss_event(
        source: CaptureSource,
        timestamp: Timestamp,
        lost_events: u64,
    ) -> CaptureEvent {
        CaptureEvent::Loss(CapturedLoss {
            timestamp,
            origin: CaptureOrigin::from_source(source),
            enforcement_evidence: EnforcementEvidence::default(),
            loss: CaptureLoss {
                lost_events,
                reason: "test output loss".to_string(),
            },
        })
    }

    fn timestamp(monotonic_ns: u64) -> Timestamp {
        Timestamp {
            monotonic_ns,
            wall_time_unix_ns: i64::try_from(monotonic_ns).expect("test timestamp must fit i64"),
        }
    }
}
