use probe_core::{
    CaptureOrigin, CaptureSource, Direction, EnforcementEvidence, FlowContext, FlowIdentity, Gap,
    ObservationOnlyReason, Timestamp,
};

use crate::{
    CaptureEvent, CapturedGap, EnforcementEvidencePropagation, PlaintextEvent, PlaintextEventKind,
    PlaintextGap,
};

use crate::bounded_recency::BoundedRecencyMap;

use super::bridge::is_unresolved_libssl_flow;

const DEFAULT_MAX_TRACKED_TLS_PLAINTEXT_FLOWS: usize = 8192;

#[derive(Debug)]
pub(in crate::tls::plaintext) struct TlsPlaintextLossTracker {
    flows: BoundedRecencyMap<TlsPlaintextFlowKey, TrackedTlsPlaintextFlow>,
}

impl TlsPlaintextLossTracker {
    fn bounded(max_tracked_flows: usize) -> Self {
        Self {
            flows: BoundedRecencyMap::new(max_tracked_flows),
        }
    }

    pub(in crate::tls::plaintext) fn observe_event(&mut self, event: &PlaintextEvent) {
        match &event.kind {
            PlaintextEventKind::Bytes(chunk) => {
                if is_unresolved_libssl_flow(&chunk.flow) {
                    return;
                }
                self.upsert(
                    &chunk.flow,
                    chunk.direction,
                    chunk.stream_offset.saturating_add(chunk.bytes.len() as u64),
                );
            }
            PlaintextEventKind::Gap(gap) => {
                if is_unresolved_libssl_flow(&gap.flow) {
                    return;
                }
                self.upsert(&gap.flow, gap.gap.direction, gap_stream_offset(gap));
            }
            PlaintextEventKind::ConnectionOpened(_) | PlaintextEventKind::ConnectionClosed(_) => {}
        }
    }

    pub(in crate::tls::plaintext) fn finish_checkpoint(
        &mut self,
        timestamp: Timestamp,
        lost_events: Option<u64>,
    ) -> Vec<CaptureEvent> {
        let events = lost_events
            .map(|lost_events| {
                self.loss_targets()
                    .map(|tracked| tls_plaintext_output_loss_gap(timestamp, tracked, lost_events))
                    .collect()
            })
            .unwrap_or_default();
        self.clear();
        events
    }

    fn loss_targets(&self) -> impl Iterator<Item = &TrackedTlsPlaintextFlow> {
        self.flows.values_by_recency()
    }

    fn upsert(&mut self, flow: &FlowContext, direction: Direction, stream_offset: u64) {
        let key = TlsPlaintextFlowKey {
            flow_id: flow.id.clone(),
            direction,
        };
        let stream_offset = self
            .flows
            .get(&key)
            .map(|tracked| tracked.stream_offset.max(stream_offset))
            .unwrap_or(stream_offset);
        self.flows.insert(
            key,
            TrackedTlsPlaintextFlow {
                flow: flow.clone(),
                direction,
                stream_offset,
            },
        );
    }

    fn clear(&mut self) {
        self.flows.clear();
    }
}

impl Default for TlsPlaintextLossTracker {
    fn default() -> Self {
        Self::bounded(DEFAULT_MAX_TRACKED_TLS_PLAINTEXT_FLOWS)
    }
}

#[derive(Debug)]
struct TrackedTlsPlaintextFlow {
    flow: FlowContext,
    direction: Direction,
    stream_offset: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct TlsPlaintextFlowKey {
    flow_id: FlowIdentity,
    direction: Direction,
}

fn tls_plaintext_output_loss_gap(
    timestamp: Timestamp,
    tracked: &TrackedTlsPlaintextFlow,
    lost_events: u64,
) -> CaptureEvent {
    let reason = format!(
        "eBPF libssl uprobe plaintext output ring buffer lost {lost_events} event(s) after this TLS plaintext flow was observed in the current output-loss checkpoint window; affected TLS record, plaintext bytes, and next stream offset are unknown"
    );
    let enforcement_evidence = EnforcementEvidence::observation_only_with_detail(
        ObservationOnlyReason::ProviderCaptureLoss,
        reason.clone(),
    );
    CaptureEvent::Gap(CapturedGap {
        timestamp,
        flow: tracked.flow.clone(),
        origin: CaptureOrigin::from_source(CaptureSource::LibsslUprobe),
        enforcement_evidence,
        enforcement_evidence_propagation: EnforcementEvidencePropagation::Flow,
        gap: Gap {
            direction: tracked.direction,
            expected_offset: tracked.stream_offset,
            next_offset: None,
            reason,
        },
    })
}

fn gap_stream_offset(gap: &PlaintextGap) -> u64 {
    gap.gap.next_offset.unwrap_or(gap.gap.expected_offset)
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use probe_core::{AddressPort, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol};

    use crate::{PlaintextChunk, PlaintextGap, PlaintextSource};

    use super::*;

    #[test]
    fn output_loss_gaps_fan_out_to_tls_plaintext_flows_in_checkpoint_window_without_advancing_offsets()
     {
        let mut tracker = TlsPlaintextLossTracker::bounded(8);
        tracker.observe_event(&PlaintextEvent::bytes(
            PlaintextSource::LibsslUprobe,
            PlaintextChunk {
                timestamp: timestamp(1),
                flow: flow("flow-a"),
                direction: Direction::Outbound,
                stream_offset: 100,
                bytes: Bytes::from_static(b"GET /"),
                attribution_confidence: 90,
                degraded: true,
                degradation_reason: Some("best-effort TLS plaintext attribution".to_string()),
            },
        ));
        tracker.observe_event(&PlaintextEvent::gap(
            PlaintextSource::LibsslUprobe,
            PlaintextGap::new(
                timestamp(2),
                flow("flow-b"),
                Gap {
                    direction: Direction::Inbound,
                    expected_offset: 20,
                    next_offset: Some(30),
                    reason: "truncated TLS plaintext sample".to_string(),
                },
            ),
        ));

        let events = tracker.finish_checkpoint(timestamp(3), Some(4));

        assert_eq!(events.len(), 2);
        assert!(events.iter().all(|event| matches!(
            event,
            CaptureEvent::Gap(gap)
                if gap.origin.source() == CaptureSource::LibsslUprobe
                    && gap.enforcement_evidence_propagation
                        == EnforcementEvidencePropagation::Flow
                    && gap.enforcement_evidence
                        .destructive_enforcement_rejection_reason()
                        .is_some_and(|reason| reason.contains("lost observations"))
                    && gap.gap.next_offset.is_none()
                    && gap.gap.reason.contains("lost 4 event(s)")
                    && gap.gap.reason.contains("affected TLS record")
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            CaptureEvent::Gap(gap)
                if gap.flow.id == FlowIdentity("flow-a".to_string())
                    && gap.gap.direction == Direction::Outbound
                    && gap.gap.expected_offset == 105
        )));
        assert!(events.iter().any(|event| matches!(
            event,
            CaptureEvent::Gap(gap)
                if gap.flow.id == FlowIdentity("flow-b".to_string())
                    && gap.gap.direction == Direction::Inbound
                    && gap.gap.expected_offset == 30
        )));

        assert!(tracker.finish_checkpoint(timestamp(4), Some(1)).is_empty());
    }

    #[test]
    fn unresolved_tls_plaintext_flows_are_not_tracked_for_output_loss_fan_out() {
        let mut tracker = TlsPlaintextLossTracker::bounded(8);
        tracker.observe_event(&PlaintextEvent::bytes(
            PlaintextSource::LibsslUprobe,
            PlaintextChunk {
                timestamp: timestamp(1),
                flow: unresolved_flow("unresolved"),
                direction: Direction::Outbound,
                stream_offset: 0,
                bytes: Bytes::from_static(b"GET /"),
                attribution_confidence: 0,
                degraded: true,
                degradation_reason: Some("unresolved TLS plaintext flow".to_string()),
            },
        ));

        assert!(tracker.finish_checkpoint(timestamp(2), Some(1)).is_empty());
    }

    #[test]
    fn no_loss_checkpoint_clears_tls_plaintext_window_without_emitting_gaps() {
        let mut tracker = TlsPlaintextLossTracker::bounded(8);
        tracker.observe_event(&bytes_event(
            flow("window-flow"),
            Direction::Outbound,
            10,
            b"GET /",
        ));

        assert!(tracker.finish_checkpoint(timestamp(2), None).is_empty());
        assert!(tracker.finish_checkpoint(timestamp(3), Some(1)).is_empty());
    }

    #[test]
    fn tracker_evicts_oldest_tls_plaintext_flow_when_capacity_is_exceeded() {
        let mut tracker = TlsPlaintextLossTracker::bounded(1);
        tracker.observe_event(&bytes_event(
            flow("old-flow"),
            Direction::Outbound,
            0,
            b"old",
        ));
        tracker.observe_event(&bytes_event(
            flow("new-flow"),
            Direction::Outbound,
            0,
            b"new",
        ));

        let events = tracker.finish_checkpoint(timestamp(3), Some(1));

        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            CaptureEvent::Gap(gap) if gap.flow.id == FlowIdentity("new-flow".to_string())
        ));
    }

    fn bytes_event(
        flow: FlowContext,
        direction: Direction,
        stream_offset: u64,
        bytes: &'static [u8],
    ) -> PlaintextEvent {
        PlaintextEvent::bytes(
            PlaintextSource::LibsslUprobe,
            PlaintextChunk {
                timestamp: timestamp(1),
                flow,
                direction,
                stream_offset,
                bytes: Bytes::from_static(bytes),
                attribution_confidence: 90,
                degraded: true,
                degradation_reason: Some("best-effort TLS plaintext attribution".to_string()),
            },
        )
    }

    fn flow(id: &str) -> FlowContext {
        FlowContext {
            id: FlowIdentity(id.to_string()),
            process: ProcessContext {
                identity: ProcessIdentity {
                    pid: 22,
                    tgid: 22,
                    start_time_ticks: 1,
                    boot_id: "boot".to_string(),
                    exe_path: "/usr/bin/curl".to_string(),
                    cmdline_hash: "hash".to_string(),
                    uid: 33,
                    gid: 44,
                    cgroup: None,
                    systemd_service: None,
                    container_id: None,
                    runtime_hint: None,
                },
                name: "curl".to_string(),
                cmdline: vec!["curl".to_string()],
            },
            local: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 50_000,
            },
            remote: AddressPort {
                address: "127.0.0.1".to_string(),
                port: 443,
            },
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: None,
            attribution_confidence: 90,
        }
    }

    fn unresolved_flow(id: &str) -> FlowContext {
        FlowContext {
            id: FlowIdentity(id.to_string()),
            local: AddressPort {
                address: "0.0.0.0".to_string(),
                port: 0,
            },
            remote: AddressPort {
                address: "0.0.0.0".to_string(),
                port: 0,
            },
            attribution_confidence: 0,
            ..flow(id)
        }
    }

    fn timestamp(monotonic_ns: u64) -> Timestamp {
        Timestamp {
            monotonic_ns,
            wall_time_unix_ns: monotonic_ns as i64,
        }
    }
}
