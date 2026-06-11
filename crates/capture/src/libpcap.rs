mod decoder;
mod flow;

use std::collections::VecDeque;

use bytes::Bytes;
use pcap::{Active, Capture, Device, Linktype, PacketHeader};
use probe_core::{CapabilityKind, CapabilityState, CaptureSource, FlowContext, Timestamp};

use crate::ProcessResolver;
use crate::{CaptureError, CaptureEvent, CaptureProvider, CaptureProviderKind, CapturedBytes};

use decoder::DecodedTcpSegment;
use flow::{FlowObservation, FlowTracker};

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
    process_resolver: Option<Box<dyn ProcessResolver>>,
    pending_events: VecDeque<CaptureEvent>,
    packet_sequence: u64,
}

impl LibpcapProvider {
    pub fn open(config: LibpcapConfig) -> Result<Self, CaptureError> {
        Self::open_with_process_resolver(config, None)
    }

    pub fn open_with_process_resolver(
        config: LibpcapConfig,
        process_resolver: Option<Box<dyn ProcessResolver>>,
    ) -> Result<Self, CaptureError> {
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
        let datalink = capture.get_datalink();
        Ok(Self {
            capture,
            datalink,
            flows: FlowTracker::default(),
            process_resolver,
            pending_events: VecDeque::new(),
            packet_sequence: 0,
        })
    }

    pub fn probe(config: &LibpcapConfig) -> Result<(), CaptureError> {
        Self::open(config.clone()).map(|_| ())
    }

    fn next_decoded(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        loop {
            if let Some(event) = self.pending_events.pop_front() {
                return Ok(Some(event));
            }
            let (header, data) = match self.capture.next_packet() {
                Ok(packet) => (*packet.header, packet.data.to_vec()),
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(error) => return Err(pcap_error("read packet", error)),
            };
            let Some(decoded) = DecodedTcpSegment::decode(self.datalink, &data) else {
                continue;
            };
            let timestamp = self.next_timestamp(&header);
            if decoded.payload.is_empty() {
                if decoded.has_lifecycle_signal() {
                    self.invalidate_process_resolution();
                    for closed_flow in self.observe_lifecycle(&decoded, timestamp) {
                        self.pending_events
                            .push_back(connection_closed_event(timestamp, closed_flow));
                    }
                    if let Some(event) = self.pending_events.pop_front() {
                        return Ok(Some(event));
                    }
                }
                continue;
            }
            if decoded.has_syn() {
                self.invalidate_process_resolution();
            }
            let observed = self.observe_flow(&decoded, timestamp);
            if decoded.has_fin() || decoded.has_rst() {
                self.invalidate_process_resolution();
            }
            let event = self.event_from_decoded(timestamp, decoded, observed);
            return Ok(Some(event));
        }
    }

    fn next_timestamp(&mut self, header: &PacketHeader) -> Timestamp {
        self.packet_sequence = self.packet_sequence.saturating_add(1);
        let wall_time_unix_ns = (header.ts.tv_sec as i128)
            .saturating_mul(1_000_000_000)
            .saturating_add((header.ts.tv_usec as i128).saturating_mul(1_000));
        Timestamp {
            monotonic_ns: self.packet_sequence,
            wall_time_unix_ns,
        }
    }

    fn event_from_decoded(
        &mut self,
        timestamp: Timestamp,
        decoded: DecodedTcpSegment<'_>,
        observed: FlowObservation,
    ) -> CaptureEvent {
        let mut sequence = event_sequence_from_observation(timestamp, decoded, observed);
        let first = sequence
            .pop_front()
            .expect("decoded payload must produce at least one bytes event");
        self.pending_events.extend(sequence);
        first
    }

    fn observe_flow(
        &mut self,
        decoded: &DecodedTcpSegment<'_>,
        timestamp: Timestamp,
    ) -> FlowObservation {
        self.flows
            .observe(decoded, timestamp, &mut self.process_resolver)
    }

    fn observe_lifecycle(
        &mut self,
        decoded: &DecodedTcpSegment<'_>,
        timestamp: Timestamp,
    ) -> Vec<FlowContext> {
        self.flows.observe_lifecycle(decoded, timestamp)
    }

    fn invalidate_process_resolution(&mut self) {
        if let Some(process_resolver) = self.process_resolver.as_deref_mut() {
            process_resolver.invalidate_cached_resolution();
        }
    }
}

fn event_sequence_from_observation(
    timestamp: Timestamp,
    decoded: DecodedTcpSegment<'_>,
    observed: FlowObservation,
) -> VecDeque<CaptureEvent> {
    let mut sequence = observed
        .closed_before
        .into_iter()
        .map(|flow| connection_closed_event(timestamp, flow))
        .collect::<VecDeque<_>>();
    sequence.push_back(CaptureEvent::Bytes(CapturedBytes {
        timestamp,
        flow: observed.flow,
        source: CaptureSource::Libpcap,
        provider: CaptureProviderKind::Libpcap,
        direction: observed.direction,
        stream_offset: 0,
        bytes: Bytes::copy_from_slice(decoded.payload),
        attribution_confidence: observed.attribution_confidence,
        degraded: true,
        degradation_reason: Some(degradation_reason(observed.attribution_failure.as_deref())),
    }));
    if let Some(closed_flow) = observed.closed_after {
        sequence.push_back(connection_closed_event(timestamp, closed_flow));
    }
    sequence
}

impl CaptureProvider for LibpcapProvider {
    fn name(&self) -> &'static str {
        "libpcap"
    }

    fn kind(&self) -> CaptureProviderKind {
        CaptureProviderKind::Libpcap
    }

    fn source(&self) -> CaptureSource {
        CaptureSource::Libpcap
    }

    fn capabilities(&self) -> Vec<CapabilityState> {
        vec![CapabilityState::available(CapabilityKind::Libpcap)]
    }

    fn next(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        self.next_decoded()
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
        source: CaptureSource::Libpcap,
        provider: CaptureProviderKind::Libpcap,
    }
}

fn degradation_reason(attribution_failure: Option<&str>) -> String {
    let base = "libpcap fallback has packet-level payload with best-effort attribution and no TCP reassembly";
    match attribution_failure {
        Some(reason) => format!("{base}; process attribution failed: {reason}"),
        None => base.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use probe_core::{
        AddressPort, Direction, FlowIdentity, ProcessContext, ProcessIdentity, TransportProtocol,
    };

    use super::*;
    use crate::libpcap::decoder::TcpFlags;

    #[test]
    fn event_sequence_places_stale_close_before_new_bytes() {
        let timestamp = timestamp(7);
        let stale_flow = demo_flow(1, 10);
        let new_flow = demo_flow(2, 11);
        let sequence = event_sequence_from_observation(
            timestamp,
            decoded_payload(),
            FlowObservation {
                direction: Direction::Outbound,
                flow: new_flow.clone(),
                attribution_confidence: 60,
                attribution_failure: None,
                closed_before: vec![stale_flow.clone()],
                closed_after: None,
            },
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
        let sequence = event_sequence_from_observation(
            timestamp,
            decoded_payload(),
            FlowObservation {
                direction: Direction::Outbound,
                flow: flow.clone(),
                attribution_confidence: 60,
                attribution_failure: None,
                closed_before: Vec::new(),
                closed_after: Some(flow.clone()),
            },
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

    fn decoded_payload() -> DecodedTcpSegment<'static> {
        DecodedTcpSegment {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            source_port: 50_000,
            destination_port: 80,
            sequence: 1,
            flags: TcpFlags {
                syn: false,
                fin: false,
                rst: false,
            },
            payload: b"GET / HTTP/1.1\r\n\r\n",
        }
    }

    fn timestamp(monotonic_ns: u64) -> Timestamp {
        Timestamp {
            monotonic_ns,
            wall_time_unix_ns: i128::from(monotonic_ns),
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
