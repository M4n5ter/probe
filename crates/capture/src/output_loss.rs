use probe_core::{
    AddressPort, CaptureLoss, CaptureSource, EnforcementEvidence, FlowContext, FlowIdentity,
    ObservationOnlyReason, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
};

use crate::{CaptureEvent, CaptureProviderKind, CapturedLoss};

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
    provider: CaptureProviderKind,
    reason: String,
) -> CaptureEvent {
    CaptureEvent::Loss(CapturedLoss {
        timestamp,
        flow: unknown_provider_loss_flow(timestamp.monotonic_ns),
        source,
        provider,
        enforcement_evidence: EnforcementEvidence::observation_only_with_detail(
            ObservationOnlyReason::EbpfCaptureLoss,
            reason.clone(),
        ),
        loss: CaptureLoss {
            lost_events,
            reason,
        },
    })
}

fn unknown_provider_loss_flow(start_monotonic_ns: u64) -> FlowContext {
    let process = ProcessContext {
        identity: ProcessIdentity {
            pid: 0,
            tgid: 0,
            start_time_ticks: 0,
            boot_id: String::new(),
            exe_path: String::new(),
            cmdline_hash: String::new(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        },
        name: "unknown".to_string(),
        cmdline: Vec::new(),
    };
    let local = unknown_endpoint();
    let remote = unknown_endpoint();
    FlowContext {
        id: FlowIdentity::stable(
            &process.identity,
            &local,
            &remote,
            TransportProtocol::Tcp,
            start_monotonic_ns,
            None,
        ),
        process,
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns,
        socket_cookie: None,
        attribution_confidence: 0,
    }
}

fn unknown_endpoint() -> AddressPort {
    AddressPort {
        address: "0.0.0.0".to_string(),
        port: 0,
    }
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
