use std::collections::VecDeque;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pcap::{Active, Capture, Device, Linktype, PacketHeader};
use probe_core::{CapabilityKind, CapabilityState, CaptureSource, Timestamp};

use crate::ProcessResolver;
use crate::{CaptureError, CaptureEvent, CapturePoll, CaptureProvider};

use super::decoder::DecodedTcpSegment;
use super::flow::{
    FlowClosure, FlowEnd, FlowLifecycleObservation, FlowPayloadObservation, FlowTracker,
};
use super::stream::{StreamTracker, degradation_reason};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LibpcapConfig {
    pub interface: Option<String>,
    pub bpf_filter: String,
    pub snaplen: i32,
    pub promisc: bool,
    pub immediate_mode: bool,
    pub read_timeout_ms: i32,
    pub buffer_size: Option<i32>,
}

impl Default for LibpcapConfig {
    fn default() -> Self {
        Self {
            interface: None,
            bpf_filter: "tcp".to_string(),
            snaplen: 65_535,
            promisc: false,
            immediate_mode: true,
            read_timeout_ms: 1_000,
            buffer_size: None,
        }
    }
}

pub struct LibpcapProvider {
    capture: Capture<Active>,
    datalink: Linktype,
    flows: FlowTracker,
    streams: StreamTracker,
    process_resolver: Option<Box<dyn ProcessResolver>>,
    pending_events: VecDeque<CaptureEvent>,
    pending_flush: PendingStreamFlush,
    packet_sequence: u64,
}

struct PendingStreamFlush {
    interval: Duration,
    deadline: Option<Instant>,
}

impl PendingStreamFlush {
    fn from_read_timeout_ms(read_timeout_ms: i32) -> Self {
        Self {
            interval: Duration::from_millis(read_timeout_ms.max(0) as u64),
            deadline: None,
        }
    }

    fn observe(&mut self, has_pending: bool, now: Instant) {
        if has_pending {
            self.deadline.get_or_insert(now + self.interval);
        } else {
            self.deadline = None;
        }
    }

    fn should_flush(&mut self, has_pending: bool, now: Instant) -> bool {
        self.observe(has_pending, now);
        self.deadline.is_some_and(|deadline| now >= deadline)
    }

    fn after_flush(&mut self, has_pending: bool, now: Instant) {
        self.deadline = None;
        self.observe(has_pending, now);
    }
}

impl LibpcapProvider {
    pub fn open(config: LibpcapConfig) -> Result<Self, CaptureError> {
        Self::open_with_process_resolver(config, None)
    }

    pub fn open_with_process_resolver(
        config: LibpcapConfig,
        process_resolver: Option<Box<dyn ProcessResolver>>,
    ) -> Result<Self, CaptureError> {
        let pending_flush = PendingStreamFlush::from_read_timeout_ms(config.read_timeout_ms);
        let device = resolve_device(config.interface.as_deref())?;
        let mut inactive = Capture::from_device(device)
            .map_err(|error| pcap_error("create capture", error))?
            .snaplen(config.snaplen)
            .promisc(config.promisc)
            .timeout(config.read_timeout_ms)
            .immediate_mode(config.immediate_mode);
        if let Some(buffer_size) = config.buffer_size {
            inactive = inactive.buffer_size(buffer_size);
        }
        let mut capture = inactive
            .open()
            .map_err(|error| pcap_error("open capture", error))?;
        if !config.bpf_filter.trim().is_empty() {
            capture
                .filter(&config.bpf_filter, true)
                .map_err(|error| pcap_error("install BPF filter", error))?;
        }
        let capture = capture
            .setnonblock()
            .map_err(|error| pcap_error("set nonblocking mode", error))?;
        let datalink = capture.get_datalink();
        Ok(Self {
            capture,
            datalink,
            flows: FlowTracker::default(),
            streams: StreamTracker::default(),
            process_resolver,
            pending_events: VecDeque::new(),
            pending_flush,
            packet_sequence: 0,
        })
    }

    pub fn probe(config: &LibpcapConfig) -> Result<(), CaptureError> {
        Self::open(config.clone()).map(|_| ())
    }

    fn poll_decoded(&mut self) -> Result<CapturePoll, CaptureError> {
        if let Some(event) = self.pending_events.pop_front() {
            return Ok(CapturePoll::event(event));
        }
        if let Some(poll) = self.flush_pending_if_due() {
            return Ok(poll);
        }
        let (header, data) = match self.capture.next_packet() {
            Ok(packet) => (*packet.header, packet.data.to_vec()),
            Err(pcap::Error::TimeoutExpired) => {
                return Ok(self.flush_pending_or_idle());
            }
            Err(error) => return Err(pcap_error("read packet", error)),
        };
        let Some(decoded) = DecodedTcpSegment::decode(self.datalink, &data) else {
            self.refresh_pending_flush_deadline();
            return Ok(CapturePoll::Progress);
        };
        let timestamp = self.next_timestamp(&header);
        if decoded.payload.is_empty() {
            if decoded.has_lifecycle_signal() {
                let observation = self.observe_lifecycle(&decoded, timestamp);
                self.pending_events
                    .extend(event_sequence_from_lifecycle_observation(
                        &mut self.streams,
                        timestamp,
                        observation,
                    ));
                if let Some(event) = self.pending_events.pop_front() {
                    self.refresh_pending_flush_deadline();
                    return Ok(CapturePoll::event(event));
                }
            }
            self.refresh_pending_flush_deadline();
            return Ok(CapturePoll::Progress);
        }
        let observation = self.observe_flow(&decoded, timestamp);
        let events = self.event_sequence_from_payload_observation(timestamp, decoded, observation);
        self.pending_events.extend(events);
        let poll = self
            .pending_events
            .pop_front()
            .map(CapturePoll::event)
            .unwrap_or(CapturePoll::Progress);
        self.refresh_pending_flush_deadline();
        Ok(poll)
    }

    fn flush_pending_or_idle(&mut self) -> CapturePoll {
        self.flush_pending_if_due().unwrap_or(CapturePoll::Idle)
    }

    fn flush_pending_if_due(&mut self) -> Option<CapturePoll> {
        if self
            .pending_flush
            .should_flush(self.streams.has_pending(), Instant::now())
        {
            let timestamp = self.timeout_timestamp();
            self.pending_events
                .extend(self.streams.flush_pending(timestamp));
            self.pending_flush
                .after_flush(self.streams.has_pending(), Instant::now());
            if let Some(event) = self.pending_events.pop_front() {
                return Some(CapturePoll::event(event));
            }
            return Some(CapturePoll::Progress);
        }
        None
    }

    fn refresh_pending_flush_deadline(&mut self) {
        self.pending_flush
            .observe(self.streams.has_pending(), Instant::now());
    }

    fn next_timestamp(&mut self, header: &PacketHeader) -> Timestamp {
        self.packet_sequence = self.packet_sequence.saturating_add(1);
        let wall_time_unix_ns = header
            .ts
            .tv_sec
            .saturating_mul(1_000_000_000)
            .saturating_add(header.ts.tv_usec.saturating_mul(1_000));
        Timestamp {
            monotonic_ns: self.packet_sequence,
            wall_time_unix_ns,
        }
    }

    fn timeout_timestamp(&mut self) -> Timestamp {
        self.packet_sequence = self.packet_sequence.saturating_add(1);
        let wall_time_unix_ns = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| i64::try_from(duration.as_nanos()).unwrap_or(i64::MAX))
            .unwrap_or_default();
        Timestamp {
            monotonic_ns: self.packet_sequence,
            wall_time_unix_ns,
        }
    }

    fn event_sequence_from_payload_observation(
        &mut self,
        timestamp: Timestamp,
        decoded: DecodedTcpSegment<'_>,
        observation: FlowPayloadObservation,
    ) -> VecDeque<CaptureEvent> {
        event_sequence_from_payload_observation(&mut self.streams, timestamp, decoded, observation)
    }

    fn observe_flow(
        &mut self,
        decoded: &DecodedTcpSegment<'_>,
        timestamp: Timestamp,
    ) -> FlowPayloadObservation {
        self.flows
            .observe(decoded, timestamp, &mut self.process_resolver)
    }

    fn observe_lifecycle(
        &mut self,
        decoded: &DecodedTcpSegment<'_>,
        timestamp: Timestamp,
    ) -> FlowLifecycleObservation {
        self.flows
            .observe_lifecycle(decoded, timestamp, &mut self.process_resolver)
    }
}

fn event_sequence_from_payload_observation(
    streams: &mut StreamTracker,
    timestamp: Timestamp,
    decoded: DecodedTcpSegment<'_>,
    observation: FlowPayloadObservation,
) -> VecDeque<CaptureEvent> {
    let mut sequence = VecDeque::new();
    for closure in observation.before_payload_closures {
        append_closure_events(&mut sequence, streams, timestamp, &closure);
    }
    let reason = degradation_reason(observation.payload.attribution_failure.as_deref());
    sequence.extend(streams.ingest_segment(timestamp, &decoded, &observation.payload, reason));
    if let Some(after_payload) = observation.after_payload {
        append_flow_end_events(&mut sequence, streams, timestamp, &after_payload);
    }
    sequence
}

fn event_sequence_from_lifecycle_observation(
    streams: &mut StreamTracker,
    timestamp: Timestamp,
    observation: FlowLifecycleObservation,
) -> VecDeque<CaptureEvent> {
    let mut sequence = VecDeque::new();
    for closure in observation.before_lifecycle_closures {
        append_closure_events(&mut sequence, streams, timestamp, &closure);
    }
    if let Some(after_lifecycle) = observation.after_lifecycle {
        append_flow_end_events(&mut sequence, streams, timestamp, &after_lifecycle);
    }
    sequence
}

fn append_flow_end_events(
    sequence: &mut VecDeque<CaptureEvent>,
    streams: &mut StreamTracker,
    timestamp: Timestamp,
    flow_end: &FlowEnd,
) {
    match flow_end {
        FlowEnd::Close(closure) => {
            append_closure_events(sequence, streams, timestamp, closure);
        }
        FlowEnd::Finalize(finalization) => {
            sequence.extend(streams.finalize_direction(timestamp, finalization));
        }
    }
}

fn append_closure_events(
    sequence: &mut VecDeque<CaptureEvent>,
    streams: &mut StreamTracker,
    timestamp: Timestamp,
    closure: &FlowClosure,
) {
    sequence.extend(streams.close_flow(timestamp, closure));
    sequence.push_back(connection_closed_event(timestamp, closure.flow.clone()));
}

impl CaptureProvider for LibpcapProvider {
    fn name(&self) -> &'static str {
        "libpcap"
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::available(CapabilityKind::Libpcap)]
    }

    fn poll_next(&mut self) -> Result<CapturePoll, CaptureError> {
        self.poll_decoded()
    }
}

fn resolve_device(interface: Option<&str>) -> Result<Device, CaptureError> {
    match interface {
        Some(interface) => Ok(Device::from(interface)),
        None => Device::lookup()
            .map_err(|error| pcap_error("lookup default device", error))?
            .ok_or_else(|| CaptureError::provider("libpcap", "no default pcap device found")),
    }
}

fn pcap_error(action: &str, error: pcap::Error) -> CaptureError {
    CaptureError::provider("libpcap", format!("{action}: {error}"))
}

fn connection_closed_event(timestamp: Timestamp, flow: probe_core::FlowContext) -> CaptureEvent {
    CaptureEvent::ConnectionClosed {
        timestamp,
        flow,
        origin: probe_core::CaptureOrigin::from_source(CaptureSource::Libpcap),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use probe_core::{
        AddressPort, Direction, FlowContext, FlowIdentity, ProcessContext, ProcessIdentity,
        TransportProtocol,
    };

    use super::super::flow::{
        FlowCloseSequence, FlowClosure, FlowEnd, FlowFinalization, FlowLifecycleObservation,
        FlowPayload, FlowPayloadObservation,
    };
    use super::*;
    use crate::libpcap::decoder::TcpFlags;

    #[test]
    fn pending_stream_flush_waits_until_read_timeout_elapses() {
        let start = Instant::now();
        let mut pending_flush = PendingStreamFlush::from_read_timeout_ms(1_000);

        pending_flush.observe(true, start);

        assert!(!pending_flush.should_flush(true, start + Duration::from_millis(999)));
        assert!(pending_flush.should_flush(true, start + Duration::from_millis(1_000)));
    }

    #[test]
    fn pending_stream_flush_clears_deadline_when_streams_resolve() {
        let start = Instant::now();
        let mut pending_flush = PendingStreamFlush::from_read_timeout_ms(1_000);

        pending_flush.observe(true, start);
        pending_flush.observe(false, start + Duration::from_millis(500));
        pending_flush.observe(true, start + Duration::from_millis(600));

        assert!(!pending_flush.should_flush(true, start + Duration::from_millis(1_500)));
        assert!(pending_flush.should_flush(true, start + Duration::from_millis(1_600)));
    }

    #[test]
    fn event_sequence_places_stale_close_before_new_bytes() {
        let timestamp = timestamp(7);
        let stale_flow = demo_flow(1, 10);
        let new_flow = demo_flow(2, 11);
        let sequence = event_sequence_from_payload_observation(
            &mut StreamTracker::default(),
            timestamp,
            decoded_payload(),
            FlowPayloadObservation::new(
                vec![FlowClosure::new(stale_flow.clone(), Vec::new())],
                payload_observation(new_flow.clone()),
                None,
            ),
        )
        .into_iter()
        .collect::<Vec<_>>();

        assert!(matches!(
            &sequence[0],
            CaptureEvent::ConnectionClosed { flow, .. } if flow.id == stale_flow.id
        ));
        assert!(matches!(
            &sequence[1],
            CaptureEvent::Bytes(bytes) if bytes.flow.id == new_flow.id
        ));
    }

    #[test]
    fn event_sequence_places_current_close_after_payload_bytes() {
        let timestamp = timestamp(7);
        let flow = demo_flow(1, 10);
        let sequence = event_sequence_from_payload_observation(
            &mut StreamTracker::default(),
            timestamp,
            decoded_payload(),
            FlowPayloadObservation::new(
                Vec::new(),
                payload_observation(flow.clone()),
                Some(FlowEnd::close(FlowClosure::new(flow.clone(), Vec::new()))),
            ),
        )
        .into_iter()
        .collect::<Vec<_>>();

        assert!(matches!(
            &sequence[0],
            CaptureEvent::Bytes(bytes) if bytes.flow.id == flow.id
        ));
        assert!(matches!(
            &sequence[1],
            CaptureEvent::ConnectionClosed { flow: closed, .. } if closed.id == flow.id
        ));
    }

    #[test]
    fn event_sequence_flushes_pending_stream_before_connection_close() {
        let timestamp = timestamp(7);
        let flow = demo_flow(1, 10);
        let mut streams = StreamTracker::default();

        let first = event_sequence_from_payload_observation(
            &mut streams,
            timestamp,
            decoded_segment(100, b"GET "),
            payload_flow_observation(flow.clone()),
        )
        .into_iter()
        .collect::<Vec<_>>();
        let pending = event_sequence_from_payload_observation(
            &mut streams,
            timestamp,
            decoded_segment(108, b"HTTP"),
            payload_flow_observation(flow.clone()),
        )
        .into_iter()
        .collect::<Vec<_>>();
        let close_sequence = FlowCloseSequence {
            direction: Direction::Outbound,
            sequence: 112,
        };
        let close = event_sequence_from_payload_observation(
            &mut streams,
            timestamp,
            decoded_segment(112, b""),
            FlowPayloadObservation::new(
                Vec::new(),
                payload_observation(flow.clone()),
                Some(FlowEnd::close(FlowClosure::new(
                    flow.clone(),
                    vec![close_sequence],
                ))),
            ),
        )
        .into_iter()
        .collect::<Vec<_>>();

        assert!(matches!(
            &first[0],
            CaptureEvent::Bytes(bytes) if bytes.stream_offset == 0 && bytes.bytes.as_ref() == b"GET "
        ));
        assert!(pending.is_empty());
        assert!(matches!(
            &close[0],
            CaptureEvent::Gap(gap)
                if gap.gap.expected_offset == 4 && gap.gap.next_offset == Some(8)
        ));
        assert!(matches!(
            &close[1],
            CaptureEvent::Bytes(bytes) if bytes.stream_offset == 8 && bytes.bytes.as_ref() == b"HTTP"
        ));
        assert!(matches!(
            &close[2],
            CaptureEvent::ConnectionClosed { flow: closed, .. } if closed.id == flow.id
        ));
    }

    #[test]
    fn event_sequence_finalizes_half_closed_direction_before_connection_close() {
        let timestamp = timestamp(7);
        let flow = demo_flow(1, 10);
        let mut streams = StreamTracker::default();

        let first = event_sequence_from_payload_observation(
            &mut streams,
            timestamp,
            decoded_segment(100, b"GET "),
            payload_flow_observation(flow.clone()),
        )
        .into_iter()
        .collect::<Vec<_>>();
        let half_close = event_sequence_from_lifecycle_observation(
            &mut streams,
            timestamp,
            FlowLifecycleObservation::new(
                Vec::new(),
                Some(FlowEnd::finalize(FlowFinalization::new(
                    flow.clone(),
                    FlowCloseSequence {
                        direction: Direction::Outbound,
                        sequence: 108,
                    },
                ))),
            ),
        )
        .into_iter()
        .collect::<Vec<_>>();

        assert!(matches!(
            &first[0],
            CaptureEvent::Bytes(bytes) if bytes.stream_offset == 0 && bytes.bytes.as_ref() == b"GET "
        ));
        assert!(matches!(
            &half_close[0],
            CaptureEvent::Gap(gap)
                if gap.gap.expected_offset == 4 && gap.gap.next_offset == Some(8)
        ));
        assert!(!matches!(
            half_close.last(),
            Some(CaptureEvent::ConnectionClosed { .. })
        ));
    }

    fn decoded_payload() -> DecodedTcpSegment<'static> {
        decoded_segment(1, b"GET / HTTP/1.1\r\n\r\n")
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

    fn payload_flow_observation(flow: FlowContext) -> FlowPayloadObservation {
        FlowPayloadObservation::new(Vec::new(), payload_observation(flow), None)
    }

    fn payload_observation(flow: FlowContext) -> FlowPayload {
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
