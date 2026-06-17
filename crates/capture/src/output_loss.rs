use probe_core::{
    CaptureLoss, CaptureOrigin, CaptureSource, EnforcementEvidence, ObservationOnlyReason,
    Timestamp,
};

use crate::{CaptureEvent, CapturedLoss};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutputLossTracker {
    last_count: u64,
    observations_since_check: u32,
    check_interval: u32,
}

impl OutputLossTracker {
    pub(crate) const DEFAULT_CHECK_INTERVAL: u32 = 64;

    pub(crate) const fn new(check_interval: u32) -> Self {
        Self {
            last_count: 0,
            observations_since_check: 0,
            check_interval,
        }
    }

    pub(crate) fn record_observation(&mut self) {
        self.observations_since_check = self.observations_since_check.saturating_add(1);
    }

    pub(crate) fn should_check_during_drain(&self) -> bool {
        self.observations_since_check >= self.check_interval
    }

    pub(crate) fn checkpoint(&mut self, count: u64) -> Option<u64> {
        self.observations_since_check = 0;
        if count <= self.last_count {
            self.last_count = count;
            return None;
        }
        let delta = count.saturating_sub(self.last_count);
        self.last_count = count;
        Some(delta)
    }
}

impl Default for OutputLossTracker {
    fn default() -> Self {
        Self::new(Self::DEFAULT_CHECK_INTERVAL)
    }
}

pub(crate) fn provider_output_loss_event(
    timestamp: Timestamp,
    lost_events: u64,
    source: CaptureSource,
    reason: String,
) -> CaptureEvent {
    CaptureEvent::Loss(CapturedLoss {
        timestamp,
        origin: CaptureOrigin::from_source(source),
        enforcement_evidence: EnforcementEvidence::observation_only_with_detail(
            ObservationOnlyReason::ProviderCaptureLoss,
            reason.clone(),
        ),
        loss: CaptureLoss {
            lost_events,
            reason,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_loss_tracker_reports_only_positive_deltas() {
        let mut tracker = OutputLossTracker::default();

        assert_eq!(tracker.checkpoint(2), Some(2));
        assert_eq!(tracker.checkpoint(2), None);
        assert_eq!(tracker.checkpoint(5), Some(3));
    }

    #[test]
    fn output_loss_tracker_resets_baseline_when_counter_moves_backwards() {
        let mut tracker = OutputLossTracker::default();

        assert_eq!(tracker.checkpoint(5), Some(5));
        assert_eq!(tracker.checkpoint(1), None);
        assert_eq!(tracker.checkpoint(3), Some(2));
    }

    #[test]
    fn output_loss_tracker_checks_after_bounded_observation_drain() {
        let mut tracker = OutputLossTracker::new(2);

        assert!(!tracker.should_check_during_drain());
        tracker.record_observation();
        assert!(!tracker.should_check_during_drain());
        tracker.record_observation();
        assert!(tracker.should_check_during_drain());
        assert_eq!(tracker.checkpoint(1), Some(1));
        assert!(!tracker.should_check_during_drain());
    }
}
