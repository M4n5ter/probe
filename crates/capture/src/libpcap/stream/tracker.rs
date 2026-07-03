use std::collections::HashMap;

use probe_core::{Direction, FlowContext, Gap, Timestamp};

use crate::{CaptureEvent, CapturedBytes, CapturedGap};

use super::super::decoder::DecodedTcpSegment;
use super::super::flow::{FlowCloseSequence, FlowClosure, FlowFinalization, FlowPayload};
use super::assembler::{DirectionStreamAssembler, StreamPiece};
use super::budget::{PendingCount, PendingIndex};
use super::{
    FLOW_CLOSE_GAP_REASON, GLOBAL_BUFFER_LIMIT_GAP_REASON, HANDOFF_GAP_REASON,
    REORDER_TIMEOUT_GAP_REASON, StreamKey,
};

#[derive(Debug, Default)]
pub(in crate::libpcap) struct StreamTracker {
    streams: HashMap<StreamKey, StreamEntry>,
    pending: PendingIndex,
}

impl StreamTracker {
    pub(in crate::libpcap) fn ingest_segment(
        &mut self,
        timestamp: Timestamp,
        decoded: &DecodedTcpSegment<'_>,
        payload: &FlowPayload,
        degradation_reason: String,
    ) -> Vec<CaptureEvent> {
        let key = StreamKey::new(payload.flow.id.clone(), payload.direction);
        let lookup_key = key.clone();
        let mut events = {
            let entry = self.streams.entry(lookup_key).or_insert_with(|| {
                StreamEntry::new(timestamp, payload, degradation_reason.clone())
            });
            entry.refresh(timestamp, payload, degradation_reason);
            record_stream_mutation(&mut self.pending, timestamp, &key, entry, |stream| {
                stream.ingest(decoded.payload_sequence(), decoded.payload)
            })
            .events
        };
        events.extend(self.enforce_global_budget(timestamp));
        events
    }

    pub(in crate::libpcap) fn has_pending(&self) -> bool {
        self.pending.has_pending()
    }

    pub(in crate::libpcap) fn flush_pending(&mut self, timestamp: Timestamp) -> Vec<CaptureEvent> {
        self.flush_pending_with_reason(timestamp, REORDER_TIMEOUT_GAP_REASON)
    }

    pub(in crate::libpcap) fn flush_pending_for_handoff(
        &mut self,
        timestamp: Timestamp,
    ) -> Vec<CaptureEvent> {
        self.flush_pending_with_reason(timestamp, HANDOFF_GAP_REASON)
    }

    fn flush_pending_with_reason(
        &mut self,
        timestamp: Timestamp,
        reason: &'static str,
    ) -> Vec<CaptureEvent> {
        let keys = self.pending.keys();
        let mut events = Vec::new();
        for key in keys {
            let Some(entry) = self.streams.get_mut(&key) else {
                self.pending.clear(&key);
                continue;
            };
            events.extend(
                record_stream_mutation(&mut self.pending, timestamp, &key, entry, |stream| {
                    stream.flush_pending(reason)
                })
                .events,
            );
        }
        events
    }

    pub(in crate::libpcap) fn close_flow(
        &mut self,
        timestamp: Timestamp,
        closure: &FlowClosure,
    ) -> Vec<CaptureEvent> {
        let mut events = Vec::new();
        for close_sequence in &closure.finalizations {
            events.extend(self.finalize_close_sequence(
                timestamp,
                &closure.flow,
                *close_sequence,
                FLOW_CLOSE_GAP_REASON,
            ));
        }
        for direction in [Direction::Inbound, Direction::Outbound] {
            let key = StreamKey::new(closure.flow.id.clone(), direction);
            let Some(mut entry) = self.streams.remove(&key) else {
                self.pending.clear(&key);
                continue;
            };
            events.extend(record_removed_stream_mutation(
                &mut self.pending,
                timestamp,
                &key,
                &mut entry,
                |stream| stream.flush_pending(FLOW_CLOSE_GAP_REASON),
            ));
        }
        events
    }

    pub(in crate::libpcap) fn finalize_direction(
        &mut self,
        timestamp: Timestamp,
        finalization: &FlowFinalization,
    ) -> Vec<CaptureEvent> {
        self.finalize_close_sequence(
            timestamp,
            &finalization.flow,
            finalization.close_sequence,
            FLOW_CLOSE_GAP_REASON,
        )
    }

    fn enforce_global_budget(&mut self, timestamp: Timestamp) -> Vec<CaptureEvent> {
        let mut events = Vec::new();
        while self.pending.exceeds_limit() {
            let Some(key) = self.pending.pop_oldest() else {
                break;
            };
            let Some(entry) = self.streams.get_mut(&key) else {
                self.pending.clear(&key);
                continue;
            };
            let mutation =
                record_stream_mutation(&mut self.pending, timestamp, &key, entry, |stream| {
                    stream.force_gap_for_buffer_limit(GLOBAL_BUFFER_LIMIT_GAP_REASON)
                });
            let changed = mutation.before != mutation.after;
            events.extend(mutation.events);
            if !changed {
                break;
            }
        }
        events
    }

    fn finalize_close_sequence(
        &mut self,
        timestamp: Timestamp,
        flow: &FlowContext,
        close_sequence: FlowCloseSequence,
        reason: &'static str,
    ) -> Vec<CaptureEvent> {
        let key = StreamKey::new(flow.id.clone(), close_sequence.direction);
        let entry = self.streams.entry(key.clone()).or_insert_with(|| {
            StreamEntry::from_close(timestamp, flow.clone(), close_sequence.direction)
        });
        record_stream_mutation(&mut self.pending, timestamp, &key, entry, |stream| {
            stream.close_at(close_sequence.sequence, reason)
        })
        .events
    }
}

struct StreamMutation {
    events: Vec<CaptureEvent>,
    before: PendingCount,
    after: PendingCount,
}

fn record_stream_mutation(
    pending: &mut PendingIndex,
    timestamp: Timestamp,
    key: &StreamKey,
    entry: &mut StreamEntry,
    mutate: impl FnOnce(&mut DirectionStreamAssembler) -> Vec<StreamPiece>,
) -> StreamMutation {
    let before = entry.stream.pending_count();
    let pieces = mutate(&mut entry.stream);
    let after = entry.stream.pending_count();
    let events = stream_piece_events(timestamp, entry, pieces);
    pending.update(key, entry.last_activity_monotonic_ns, after);
    StreamMutation {
        events,
        before,
        after,
    }
}

fn record_removed_stream_mutation(
    pending: &mut PendingIndex,
    timestamp: Timestamp,
    key: &StreamKey,
    entry: &mut StreamEntry,
    mutate: impl FnOnce(&mut DirectionStreamAssembler) -> Vec<StreamPiece>,
) -> Vec<CaptureEvent> {
    let pieces = mutate(&mut entry.stream);
    let events = stream_piece_events(timestamp, entry, pieces);
    pending.remove(key);
    events
}

fn stream_piece_events(
    timestamp: Timestamp,
    entry: &StreamEntry,
    pieces: Vec<StreamPiece>,
) -> Vec<CaptureEvent> {
    pieces
        .into_iter()
        .map(|piece| {
            stream_piece_event(
                timestamp,
                entry.flow.clone(),
                entry.direction,
                entry.attribution_confidence,
                entry.degradation_reason.clone(),
                piece,
            )
        })
        .collect()
}

fn stream_piece_event(
    timestamp: Timestamp,
    flow: FlowContext,
    direction: Direction,
    attribution_confidence: u8,
    degradation_reason: String,
    piece: StreamPiece,
) -> CaptureEvent {
    match piece {
        StreamPiece::Bytes {
            stream_offset,
            bytes,
        } => CaptureEvent::Bytes(CapturedBytes {
            timestamp,
            flow,
            origin: probe_core::CaptureOrigin::from_source(probe_core::CaptureSource::Libpcap),
            direction,
            stream_offset,
            bytes,
            attribution_confidence,
            degraded: true,
            degradation_reason: Some(degradation_reason),
            enforcement_evidence: probe_core::EnforcementEvidence::default(),
            enforcement_evidence_propagation: crate::EnforcementEvidencePropagation::Event,
        }),
        StreamPiece::Gap {
            expected_offset,
            next_offset,
            reason,
        } => CaptureEvent::Gap(CapturedGap {
            timestamp,
            flow,
            origin: probe_core::CaptureOrigin::from_source(probe_core::CaptureSource::Libpcap),
            enforcement_evidence: probe_core::EnforcementEvidence::default(),
            enforcement_evidence_propagation: crate::EnforcementEvidencePropagation::Event,
            gap: Gap {
                direction,
                expected_offset,
                next_offset,
                reason: reason.to_string(),
            },
        }),
    }
}

pub(in crate::libpcap) fn degradation_reason(attribution_failure: Option<&str>) -> String {
    let base = "libpcap fallback uses best-effort TCP stream assembly with best-effort attribution";
    match attribution_failure {
        Some(reason) => format!("{base}; process attribution failed: {reason}"),
        None => base.to_string(),
    }
}

#[derive(Debug)]
struct StreamEntry {
    flow: FlowContext,
    direction: Direction,
    attribution_confidence: u8,
    degradation_reason: String,
    stream: DirectionStreamAssembler,
    last_activity_monotonic_ns: u64,
}

impl StreamEntry {
    fn new(timestamp: Timestamp, payload: &FlowPayload, degradation_reason: String) -> Self {
        Self {
            flow: payload.flow.clone(),
            direction: payload.direction,
            attribution_confidence: payload.attribution_confidence,
            degradation_reason,
            stream: DirectionStreamAssembler::default(),
            last_activity_monotonic_ns: timestamp.monotonic_ns,
        }
    }

    fn from_close(timestamp: Timestamp, flow: FlowContext, direction: Direction) -> Self {
        Self {
            direction,
            attribution_confidence: flow.attribution_confidence,
            degradation_reason: degradation_reason(None),
            flow,
            stream: DirectionStreamAssembler::default(),
            last_activity_monotonic_ns: timestamp.monotonic_ns,
        }
    }

    fn refresh(&mut self, timestamp: Timestamp, payload: &FlowPayload, degradation_reason: String) {
        self.flow = payload.flow.clone();
        self.direction = payload.direction;
        self.attribution_confidence = payload.attribution_confidence;
        self.degradation_reason = degradation_reason;
        self.last_activity_monotonic_ns = timestamp.monotonic_ns;
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use probe_core::{
        AddressPort, FlowIdentity, ProcessContext, ProcessIdentity, TransportProtocol,
    };

    use super::super::super::decoder::TcpFlags;
    use super::super::super::flow::FlowCloseSequence;
    use super::super::MAX_TOTAL_PENDING_SEGMENTS;
    use super::*;

    #[test]
    fn finalization_before_stream_entry_preserves_close_boundary() {
        let timestamp = timestamp(7);
        let flow = demo_flow(1, 10);
        let mut streams = StreamTracker::default();

        let close_sequence = FlowCloseSequence {
            direction: Direction::Outbound,
            sequence: 100,
        };
        assert!(
            streams
                .finalize_direction(
                    timestamp,
                    &FlowFinalization::new(flow.clone(), close_sequence),
                )
                .is_empty()
        );

        let events = streams.ingest_segment(
            timestamp,
            &decoded_segment(96, b"goodbad"),
            &payload_for(flow),
            degradation_reason(None),
        );

        assert_eq!(events.len(), 1);
        assert!(matches!(
            &events[0],
            CaptureEvent::Bytes(bytes)
                if bytes.stream_offset == 0 && bytes.bytes.as_ref() == b"good"
        ));
        assert!(!streams.has_pending());
    }

    #[test]
    fn close_flow_emits_tail_gap_after_late_partial_payload() {
        let timestamp = timestamp(7);
        let flow = demo_flow(1, 10);
        let mut streams = StreamTracker::default();
        let close_sequence = FlowCloseSequence {
            direction: Direction::Outbound,
            sequence: 100,
        };

        assert!(
            streams
                .finalize_direction(
                    timestamp,
                    &FlowFinalization::new(flow.clone(), close_sequence),
                )
                .is_empty()
        );
        let bytes = streams.ingest_segment(
            timestamp,
            &decoded_segment(96, b"ok"),
            &payload_for(flow.clone()),
            degradation_reason(None),
        );
        let closed = streams.close_flow(
            timestamp,
            &FlowClosure::new(flow.clone(), vec![close_sequence]),
        );

        assert!(matches!(
            &bytes[0],
            CaptureEvent::Bytes(payload)
                if payload.stream_offset == 0 && payload.bytes.as_ref() == b"ok"
        ));
        assert!(matches!(
            &closed[0],
            CaptureEvent::Gap(gap)
                if gap.flow.id == flow.id
                    && gap.gap.expected_offset == 2
                    && gap.gap.next_offset == Some(4)
        ));
        assert!(!streams.has_pending());
    }

    #[test]
    fn close_flow_flushes_pending_and_clears_pending_index() {
        let timestamp = timestamp(7);
        let flow = demo_flow(1, 10);
        let mut streams = StreamTracker::default();

        streams.ingest_segment(
            timestamp,
            &decoded_segment(100, b"GET "),
            &payload_for(flow.clone()),
            degradation_reason(None),
        );
        assert!(
            streams
                .ingest_segment(
                    timestamp,
                    &decoded_segment(108, b"HTTP"),
                    &payload_for(flow.clone()),
                    degradation_reason(None),
                )
                .is_empty()
        );
        assert!(streams.has_pending());

        let events = streams.close_flow(timestamp, &FlowClosure::new(flow, Vec::new()));

        assert!(matches!(
            &events[0],
            CaptureEvent::Gap(gap)
                if gap.gap.expected_offset == 4 && gap.gap.next_offset == Some(8)
        ));
        assert!(matches!(
            &events[1],
            CaptureEvent::Bytes(bytes) if bytes.stream_offset == 8 && bytes.bytes.as_ref() == b"HTTP"
        ));
        assert!(!streams.has_pending());
    }

    #[test]
    fn global_pending_budget_flushes_oldest_pending_stream() {
        let mut streams = StreamTracker::default();
        let oldest_flow = demo_flow(0, 10);
        let mut budget_events = Vec::new();

        for index in 0..=MAX_TOTAL_PENDING_SEGMENTS {
            let flow = if index == 0 {
                oldest_flow.clone()
            } else {
                demo_flow(index as u32, 10 + index as u64)
            };
            let timestamp = timestamp(index as u64 + 1);
            streams.ingest_segment(
                timestamp,
                &decoded_segment(100, b"a"),
                &payload_for(flow.clone()),
                degradation_reason(None),
            );
            budget_events = streams.ingest_segment(
                timestamp,
                &decoded_segment(102, b"b"),
                &payload_for(flow),
                degradation_reason(None),
            );
        }

        assert!(budget_events.iter().any(|event| {
            matches!(
                event,
                CaptureEvent::Gap(gap) if gap.flow.id == oldest_flow.id
            )
        }));
        assert!(budget_events.iter().any(|event| {
            matches!(
                event,
                CaptureEvent::Bytes(bytes)
                    if bytes.flow.id == oldest_flow.id && bytes.bytes.as_ref() == b"b"
            )
        }));
    }

    fn decoded_segment(sequence: u32, payload: &'static [u8]) -> DecodedTcpSegment<'static> {
        DecodedTcpSegment {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            source_port: 50_000,
            destination_port: 80,
            sequence,
            flags: TcpFlags {
                syn: false,
                fin: false,
                rst: false,
            },
            payload,
        }
    }

    fn payload_for(flow: FlowContext) -> FlowPayload {
        FlowPayload::new(Direction::Outbound, flow, 60, None)
    }

    fn timestamp(monotonic_ns: u64) -> Timestamp {
        Timestamp {
            monotonic_ns,
            wall_time_unix_ns: monotonic_ns as i64,
        }
    }

    fn demo_flow(pid: u32, start_monotonic_ns: u64) -> FlowContext {
        let process = ProcessIdentity {
            pid,
            tgid: pid,
            start_time_ticks: u64::from(pid),
            boot_id: "boot".to_string(),
            exe_path: format!("/usr/bin/{pid}"),
            cmdline_hash: "hash".to_string(),
            uid: 1000,
            gid: 1000,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "10.0.0.1".to_string(),
            port: 50_000,
        };
        let remote = AddressPort {
            address: "10.0.0.2".to_string(),
            port: 80,
        };
        FlowContext {
            id: FlowIdentity::stable(
                &process,
                &local,
                &remote,
                TransportProtocol::Tcp,
                start_monotonic_ns,
                None,
            ),
            process: ProcessContext {
                identity: process,
                name: pid.to_string(),
                cmdline: Vec::new(),
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns,
            socket_cookie: None,
            attribution_confidence: 60,
        }
    }
}
