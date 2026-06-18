use std::collections::VecDeque;

use bytes::Bytes;
use probe_core::{EnforcementEvidence, Timestamp};

use crate::{CaptureEvent, CapturedBytes, EnforcementEvidencePropagation};

#[derive(Debug, Clone)]
pub(super) struct Tls13SessionSecretBufferedBytes {
    payload: Bytes,
    segments: VecDeque<Tls13SessionSecretBufferedSegment>,
}

#[derive(Debug, Clone)]
struct Tls13SessionSecretBufferedSegment {
    bytes: CapturedBytes,
}

impl Tls13SessionSecretBufferedBytes {
    pub(super) fn from_slice(bytes: &CapturedBytes, start: usize, end: usize) -> Option<Self> {
        let bytes = slice_captured_bytes(bytes, start, end)?;
        Some(Self {
            payload: bytes.bytes.clone(),
            segments: VecDeque::from([Tls13SessionSecretBufferedSegment { bytes }]),
        })
    }

    pub(super) fn append(&mut self, bytes: &CapturedBytes) -> bool {
        if self.segments.front().is_some_and(|front| {
            front.bytes.flow.id != bytes.flow.id || front.bytes.direction != bytes.direction
        }) {
            return false;
        }
        let Some(expected_offset) = self.stream_offset().checked_add(self.payload.len() as u64)
        else {
            return false;
        };
        if expected_offset != bytes.stream_offset {
            return false;
        }
        let mut payload = Vec::with_capacity(self.payload.len() + bytes.bytes.len());
        payload.extend_from_slice(self.payload.as_ref());
        payload.extend_from_slice(bytes.bytes.as_ref());
        self.payload = Bytes::from(payload);
        self.segments.push_back(Tls13SessionSecretBufferedSegment {
            bytes: bytes.clone(),
        });
        true
    }

    pub(super) fn payload(&self) -> &[u8] {
        self.payload.as_ref()
    }

    pub(super) fn stream_offset(&self) -> u64 {
        self.segments
            .front()
            .map(|segment| segment.bytes.stream_offset)
            .unwrap_or(0)
    }

    pub(super) fn drain_prefix(&mut self, len: usize) -> Vec<CaptureEvent> {
        let mut remaining = len.min(self.payload.len());
        let mut events = Vec::new();
        while remaining > 0 {
            let Some(mut segment) = self.segments.pop_front() else {
                break;
            };
            let segment_len = segment.bytes.bytes.len();
            if segment_len <= remaining {
                remaining -= segment_len;
                events.push(CaptureEvent::Bytes(segment.bytes));
                continue;
            }
            let prefix = slice_captured_bytes(&segment.bytes, 0, remaining)
                .expect("buffered prefix length is within the segment payload");
            let suffix = slice_captured_bytes(&segment.bytes, remaining, segment_len)
                .expect("buffered suffix length is within the segment payload");
            events.push(CaptureEvent::Bytes(prefix));
            segment.bytes = suffix;
            self.segments.push_front(segment);
            remaining = 0;
        }
        self.payload = self.payload.slice(len.min(self.payload.len())..);
        events
    }

    pub(super) fn is_empty(&self) -> bool {
        self.payload.is_empty()
    }

    pub(super) fn into_bytes(self) -> CapturedBytes {
        merge_segments(
            self.segments
                .into_iter()
                .map(|segment| segment.bytes)
                .collect(),
        )
    }

    pub(super) fn into_events(self) -> Vec<CaptureEvent> {
        self.segments
            .into_iter()
            .map(|segment| CaptureEvent::Bytes(segment.bytes))
            .collect()
    }
}

pub(super) fn sliced_event(
    bytes: &CapturedBytes,
    start: usize,
    end: usize,
) -> Option<CaptureEvent> {
    (start < end)
        .then(|| slice_captured_bytes(bytes, start, end))
        .flatten()
        .map(CaptureEvent::Bytes)
}

pub(super) fn slice_captured_bytes(
    bytes: &CapturedBytes,
    start: usize,
    end: usize,
) -> Option<CapturedBytes> {
    if start > end || end > bytes.bytes.len() {
        return None;
    }
    let mut sliced = bytes.clone();
    sliced.stream_offset = bytes.stream_offset.checked_add(start as u64)?;
    sliced.bytes = bytes.bytes.slice(start..end);
    Some(sliced)
}

fn merge_segments(mut segments: VecDeque<CapturedBytes>) -> CapturedBytes {
    let Some(mut merged) = segments.pop_front() else {
        panic!("buffered bytes cannot be converted into empty captured bytes");
    };
    if segments.is_empty() {
        return merged;
    }
    let mut payload = Vec::from(merged.bytes.as_ref());
    for segment in segments {
        payload.extend_from_slice(segment.bytes.as_ref());
        merged.timestamp = latest_timestamp(merged.timestamp, segment.timestamp);
        merged.attribution_confidence = merged
            .attribution_confidence
            .min(segment.attribution_confidence);
        merged.degradation_reason =
            merge_degradation_reason(merged.degradation_reason.take(), &segment);
        merged.degraded |= segment.degraded;
        merged.enforcement_evidence = strongest_enforcement_evidence(
            merged.enforcement_evidence.clone(),
            segment.enforcement_evidence,
        );
        merged.enforcement_evidence_propagation = strongest_enforcement_evidence_propagation(
            merged.enforcement_evidence_propagation,
            segment.enforcement_evidence_propagation,
        );
    }
    merged.bytes = Bytes::from(payload);
    merged
}

fn latest_timestamp(left: Timestamp, right: Timestamp) -> Timestamp {
    if (left.monotonic_ns, left.wall_time_unix_ns) >= (right.monotonic_ns, right.wall_time_unix_ns)
    {
        left
    } else {
        right
    }
}

fn merge_degradation_reason(current: Option<String>, incoming: &CapturedBytes) -> Option<String> {
    match (
        current,
        incoming.degraded,
        incoming.degradation_reason.as_deref(),
    ) {
        (None, false, _) | (None, true, None) => None,
        (None, true, Some(incoming)) => Some(incoming.to_string()),
        (Some(current), false, _) | (Some(current), true, None) => Some(current),
        (Some(current), true, Some(incoming)) if current == incoming => Some(current),
        (Some(current), true, Some(incoming)) => Some(format!("{current}; {incoming}")),
    }
}

fn strongest_enforcement_evidence(
    current: EnforcementEvidence,
    incoming: EnforcementEvidence,
) -> EnforcementEvidence {
    if matches!(current, EnforcementEvidence::ObservationOnly { .. }) {
        current
    } else {
        incoming
    }
}

fn strongest_enforcement_evidence_propagation(
    current: EnforcementEvidencePropagation,
    incoming: EnforcementEvidencePropagation,
) -> EnforcementEvidencePropagation {
    if current.is_flow_carried() || incoming.is_flow_carried() {
        EnforcementEvidencePropagation::Flow
    } else {
        EnforcementEvidencePropagation::Event
    }
}

#[cfg(test)]
mod tests {
    use probe_core::{
        AddressPort, CaptureOrigin, CaptureSource, Direction, FlowContext, FlowIdentity,
        ObservationOnlyReason, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
    };

    use super::*;

    #[test]
    fn drained_raw_prefix_preserves_original_segment_metadata() {
        let flow = demo_flow();
        let first = captured_bytes(
            flow.clone(),
            0,
            b"abc",
            Timestamp {
                monotonic_ns: 1,
                wall_time_unix_ns: 1,
            },
            EnforcementEvidence::default(),
            EnforcementEvidencePropagation::Event,
            None,
        );
        let second = captured_bytes(
            flow,
            3,
            b"def",
            Timestamp {
                monotonic_ns: 2,
                wall_time_unix_ns: 2,
            },
            EnforcementEvidence::observation_only(
                ObservationOnlyReason::EbpfSyscallPayloadSnapshot,
            ),
            EnforcementEvidencePropagation::Flow,
            Some("second degraded"),
        );
        let mut buffered = Tls13SessionSecretBufferedBytes::from_slice(&first, 0, 3)
            .expect("first segment slice is valid");

        assert!(buffered.append(&second));
        let released = buffered.drain_prefix(4);

        let [
            CaptureEvent::Bytes(first_release),
            CaptureEvent::Bytes(second_release),
        ] = released.as_slice()
        else {
            panic!("expected two released raw byte segments: {released:?}");
        };
        assert_eq!(first_release.bytes.as_ref(), b"abc");
        assert_eq!(first_release.timestamp.monotonic_ns, 1);
        assert_eq!(
            first_release.enforcement_evidence,
            EnforcementEvidence::default()
        );
        assert_eq!(
            first_release.enforcement_evidence_propagation,
            EnforcementEvidencePropagation::Event
        );
        assert_eq!(first_release.degradation_reason, None);
        assert_eq!(second_release.bytes.as_ref(), b"d");
        assert_eq!(second_release.timestamp.monotonic_ns, 2);
        assert!(matches!(
            second_release.enforcement_evidence,
            EnforcementEvidence::ObservationOnly { .. }
        ));
        assert_eq!(
            second_release.enforcement_evidence_propagation,
            EnforcementEvidencePropagation::Flow
        );
        assert_eq!(
            second_release.degradation_reason.as_deref(),
            Some("second degraded")
        );
        assert_eq!(buffered.payload(), b"ef");
    }

    fn captured_bytes(
        flow: FlowContext,
        stream_offset: u64,
        bytes: &[u8],
        timestamp: Timestamp,
        enforcement_evidence: EnforcementEvidence,
        enforcement_evidence_propagation: EnforcementEvidencePropagation,
        degradation_reason: Option<&str>,
    ) -> CapturedBytes {
        CapturedBytes {
            timestamp,
            flow,
            origin: CaptureOrigin::from_source(CaptureSource::Libpcap),
            direction: Direction::Outbound,
            stream_offset,
            bytes: Bytes::copy_from_slice(bytes),
            attribution_confidence: 100,
            degraded: degradation_reason.is_some(),
            degradation_reason: degradation_reason.map(ToOwned::to_owned),
            enforcement_evidence,
            enforcement_evidence_propagation,
        }
    }

    fn demo_flow() -> FlowContext {
        let process = ProcessIdentity {
            pid: 1,
            tgid: 1,
            start_time_ticks: 1,
            boot_id: "boot".to_string(),
            exe_path: "/bin/demo".to_string(),
            cmdline_hash: "hash".to_string(),
            uid: 0,
            gid: 0,
            cgroup: None,
            systemd_service: None,
            container_id: None,
            runtime_hint: None,
        };
        let local = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 12345,
        };
        let remote = AddressPort {
            address: "127.0.0.1".to_string(),
            port: 443,
        };
        FlowContext {
            id: FlowIdentity::stable(
                &process,
                &local,
                &remote,
                TransportProtocol::Tcp,
                1,
                Some(1),
            ),
            process: ProcessContext {
                identity: process,
                name: "demo".to_string(),
                cmdline: vec!["demo".to_string()],
            },
            local,
            remote,
            protocol: TransportProtocol::Tcp,
            start_monotonic_ns: 1,
            socket_cookie: Some(1),
            attribution_confidence: 100,
        }
    }
}
