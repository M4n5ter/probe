use std::{
    collections::{HashMap, VecDeque},
    net::Ipv4Addr,
};

use bytes::Bytes;
use pcap::{Active, Capture, Device, Linktype, PacketHeader};
use probe_core::{
    AddressPort, CapabilityKind, CapabilityState, CaptureSource, Direction, FlowContext,
    FlowIdentity, ProcessContext, ProcessIdentity, Timestamp, TransportProtocol,
};

use crate::{CaptureError, CaptureEvent, CaptureProvider, CaptureProviderKind, CapturedBytes};

const MAX_DIRECTION_TRACKER_CONNECTIONS: usize = 16_384;

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
    directions: DirectionTracker,
    packet_sequence: u64,
}

impl LibpcapProvider {
    pub fn open(config: LibpcapConfig) -> Result<Self, CaptureError> {
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
            directions: DirectionTracker::default(),
            packet_sequence: 0,
        })
    }

    pub fn probe(config: &LibpcapConfig) -> Result<(), CaptureError> {
        Self::open(config.clone()).map(|_| ())
    }

    fn next_decoded(&mut self) -> Result<Option<CaptureEvent>, CaptureError> {
        loop {
            let (header, data) = match self.capture.next_packet() {
                Ok(packet) => (*packet.header, packet.data.to_vec()),
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(error) => return Err(pcap_error("read packet", error)),
            };
            let Some(decoded) = DecodedTcpPayload::decode(self.datalink, &data) else {
                continue;
            };
            let timestamp = self.next_timestamp(&header);
            let event = self.event_from_decoded(timestamp, decoded);
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
        decoded: DecodedTcpPayload<'_>,
    ) -> CaptureEvent {
        let direction = self.infer_direction(&decoded);
        let flow = flow_from_decoded(&decoded, direction);
        CaptureEvent::Bytes(CapturedBytes {
            timestamp,
            flow,
            source: CaptureSource::Libpcap,
            provider: CaptureProviderKind::Libpcap,
            direction,
            stream_offset: 0,
            bytes: Bytes::copy_from_slice(decoded.payload),
            attribution_confidence: 0,
            degraded: true,
            degradation_reason: Some(
                "libpcap fallback has packet-level payload without eBPF socket attribution or TCP reassembly"
                    .to_string(),
            ),
        })
    }

    fn infer_direction(&mut self, decoded: &DecodedTcpPayload<'_>) -> Direction {
        self.directions.infer_direction(decoded)
    }
}

#[derive(Debug, Default)]
struct DirectionTracker {
    clients: HashMap<ConnectionKey, Endpoint>,
    order: VecDeque<ConnectionKey>,
}

impl DirectionTracker {
    fn infer_direction(&mut self, decoded: &DecodedTcpPayload<'_>) -> Direction {
        let key = ConnectionKey::from_decoded(decoded);
        if let Some(client) = self.clients.get(&key) {
            return if decoded.source_endpoint() == *client {
                Direction::Outbound
            } else {
                Direction::Inbound
            };
        }

        let (direction, client) = infer_initial_direction(decoded);
        self.evict_oldest_if_full();
        self.order.push_back(key);
        self.clients.insert(key, client);
        direction
    }

    fn evict_oldest_if_full(&mut self) {
        if self.clients.len() < MAX_DIRECTION_TRACKER_CONNECTIONS {
            return;
        }
        if let Some(oldest) = self.order.pop_front() {
            self.clients.remove(&oldest);
        }
    }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
struct Endpoint {
    address: Ipv4Addr,
    port: u16,
}

impl Endpoint {
    fn new(address: Ipv4Addr, port: u16) -> Self {
        Self { address, port }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct ConnectionKey {
    lower: Endpoint,
    higher: Endpoint,
}

impl ConnectionKey {
    fn from_decoded(decoded: &DecodedTcpPayload<'_>) -> Self {
        let source = decoded.source_endpoint();
        let destination = decoded.destination_endpoint();
        if source <= destination {
            Self {
                lower: source,
                higher: destination,
            }
        } else {
            Self {
                lower: destination,
                higher: source,
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DecodedTcpPayload<'a> {
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    payload: &'a [u8],
}

impl<'a> DecodedTcpPayload<'a> {
    fn decode(datalink: Linktype, frame: &'a [u8]) -> Option<Self> {
        let ipv4 = ipv4_payload(datalink, frame)?;
        decode_ipv4_tcp_payload(ipv4)
    }

    fn source_endpoint(&self) -> Endpoint {
        Endpoint::new(self.source, self.source_port)
    }

    fn destination_endpoint(&self) -> Endpoint {
        Endpoint::new(self.destination, self.destination_port)
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

fn ipv4_payload(datalink: Linktype, frame: &[u8]) -> Option<&[u8]> {
    match datalink {
        Linktype::ETHERNET => ethernet_ipv4_payload(frame),
        Linktype::LINUX_SLL => linux_sll_ipv4_payload(frame),
        Linktype::LINUX_SLL2 => linux_sll2_ipv4_payload(frame),
        Linktype::RAW | Linktype::IPV4 => Some(frame),
        Linktype::NULL | Linktype::LOOP => loopback_ipv4_payload(frame),
        _ => None,
    }
}

fn ethernet_ipv4_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 14 {
        return None;
    }
    let mut offset = 14;
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    while matches!(ethertype, 0x8100 | 0x88a8 | 0x9100) {
        if frame.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }
    (ethertype == 0x0800).then_some(&frame[offset..])
}

fn linux_sll_ipv4_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 16 {
        return None;
    }
    let protocol = u16::from_be_bytes([frame[14], frame[15]]);
    (protocol == 0x0800).then_some(&frame[16..])
}

fn linux_sll2_ipv4_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 20 {
        return None;
    }
    let protocol = u16::from_be_bytes([frame[0], frame[1]]);
    (protocol == 0x0800).then_some(&frame[20..])
}

fn loopback_ipv4_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < 4 {
        return None;
    }
    let family_ne = u32::from_ne_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let family_be = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if family_ne == 2 || family_be == 2 {
        Some(&frame[4..])
    } else {
        None
    }
}

fn decode_ipv4_tcp_payload(packet: &[u8]) -> Option<DecodedTcpPayload<'_>> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < 20 || packet.len() < header_len || packet[9] != 6 {
        return None;
    }
    let flags_fragment = u16::from_be_bytes([packet[6], packet[7]]);
    if flags_fragment & 0x3fff != 0 {
        return None;
    }
    let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total_len < header_len || packet.len() < total_len {
        return None;
    }
    let tcp = &packet[header_len..total_len];
    if tcp.len() < 20 {
        return None;
    }
    let tcp_header_len = usize::from(tcp[12] >> 4) * 4;
    if tcp_header_len < 20 || tcp.len() < tcp_header_len {
        return None;
    }
    let payload = &tcp[tcp_header_len..];
    if payload.is_empty() {
        return None;
    }
    Some(DecodedTcpPayload {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        source_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        destination_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        payload,
    })
}

fn infer_initial_direction(decoded: &DecodedTcpPayload<'_>) -> (Direction, Endpoint) {
    if decoded.payload.starts_with(b"HTTP/") {
        return (Direction::Inbound, decoded.destination_endpoint());
    }
    if looks_like_http_request(decoded.payload) {
        return (Direction::Outbound, decoded.source_endpoint());
    }
    if looks_like_server_port(decoded.source_port)
        && !looks_like_server_port(decoded.destination_port)
    {
        return (Direction::Inbound, decoded.destination_endpoint());
    }
    (Direction::Outbound, decoded.source_endpoint())
}

fn looks_like_http_request(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|method| payload.starts_with(method))
}

fn looks_like_server_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8000 | 8080 | 8443)
}

fn flow_from_decoded(decoded: &DecodedTcpPayload<'_>, direction: Direction) -> FlowContext {
    let process = synthetic_libpcap_process();
    let source = AddressPort {
        address: decoded.source.to_string(),
        port: decoded.source_port,
    };
    let destination = AddressPort {
        address: decoded.destination.to_string(),
        port: decoded.destination_port,
    };
    let (local, remote) = match direction {
        Direction::Outbound => (source, destination),
        Direction::Inbound => (destination, source),
    };
    FlowContext {
        id: FlowIdentity::stable(
            &process.identity,
            &local,
            &remote,
            TransportProtocol::Tcp,
            0,
            None,
        ),
        process,
        local,
        remote,
        protocol: TransportProtocol::Tcp,
        start_monotonic_ns: 0,
        socket_cookie: None,
        attribution_confidence: 0,
    }
}

fn synthetic_libpcap_process() -> ProcessContext {
    let identity = ProcessIdentity {
        pid: 0,
        tgid: 0,
        start_time_ticks: 0,
        boot_id: "libpcap".to_string(),
        exe_path: "unknown".to_string(),
        cmdline_hash: "unknown".to_string(),
        uid: 0,
        gid: 0,
        cgroup: None,
        systemd_service: None,
        container_id: None,
        runtime_hint: Some("libpcap_fallback".to_string()),
    };
    ProcessContext {
        identity,
        name: "unknown".to_string(),
        cmdline: Vec::new(),
    }
}

#[allow(dead_code)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ethernet_ipv4_tcp_http_request_payload() {
        let frame = ethernet_ipv4_tcp_frame(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        );

        let decoded =
            DecodedTcpPayload::decode(Linktype::ETHERNET, &frame).expect("expected tcp payload");

        assert_eq!(decoded.source, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(decoded.destination, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(decoded.source_port, 50_000);
        assert_eq!(decoded.destination_port, 80);
        assert_eq!(decoded.sequence, 100);
        assert_eq!(decoded.payload, b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(infer_initial_direction(&decoded).0, Direction::Outbound);
    }

    #[test]
    fn decodes_linux_sll_ipv4_tcp_http_response_payload() {
        let packet = ipv4_tcp_packet(
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            50_000,
            200,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        );
        let mut frame = vec![0; 16];
        frame[14..16].copy_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&packet);

        let decoded =
            DecodedTcpPayload::decode(Linktype::LINUX_SLL, &frame).expect("expected tcp payload");

        assert_eq!(decoded.source, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(decoded.destination, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            decoded.payload,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        );
        assert_eq!(infer_initial_direction(&decoded).0, Direction::Inbound);
    }

    #[test]
    fn builds_stable_flow_for_opposite_http_directions() {
        let request = DecodedTcpPayload {
            source: Ipv4Addr::new(10, 0, 0, 1),
            destination: Ipv4Addr::new(10, 0, 0, 2),
            source_port: 50_000,
            destination_port: 80,
            sequence: 100,
            payload: b"GET / HTTP/1.1\r\n\r\n",
        };
        let response = DecodedTcpPayload {
            source: Ipv4Addr::new(10, 0, 0, 2),
            destination: Ipv4Addr::new(10, 0, 0, 1),
            source_port: 80,
            destination_port: 50_000,
            sequence: 200,
            payload: b"HTTP/1.1 200 OK\r\n\r\n",
        };

        let request_flow = flow_from_decoded(&request, Direction::Outbound);
        let response_flow = flow_from_decoded(&response, Direction::Inbound);

        assert_eq!(request_flow.id, response_flow.id);
        assert_eq!(request_flow.local.address, "10.0.0.1");
        assert_eq!(request_flow.remote.address, "10.0.0.2");
        assert_eq!(request_flow.attribution_confidence, 0);
    }

    #[test]
    fn direction_tracker_keeps_response_body_inbound_after_response_headers() {
        let response_headers = DecodedTcpPayload {
            source: Ipv4Addr::new(10, 0, 0, 2),
            destination: Ipv4Addr::new(10, 0, 0, 1),
            source_port: 80,
            destination_port: 50_000,
            sequence: 200,
            payload: b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n",
        };
        let response_body = DecodedTcpPayload {
            source: Ipv4Addr::new(10, 0, 0, 2),
            destination: Ipv4Addr::new(10, 0, 0, 1),
            source_port: 80,
            destination_port: 50_000,
            sequence: 240,
            payload: b"hello",
        };
        let mut tracker = DirectionTracker::default();

        assert_eq!(
            tracker.infer_direction(&response_headers),
            Direction::Inbound
        );
        assert_eq!(tracker.infer_direction(&response_body), Direction::Inbound);
    }

    #[test]
    fn skips_fragmented_or_truncated_ipv4_packets() {
        let mut fragment = ipv4_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(decode_ipv4_tcp_payload(&fragment).is_none());

        let mut truncated = ipv4_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        truncated.truncate(truncated.len() - 1);
        assert!(decode_ipv4_tcp_payload(&truncated).is_none());
    }

    fn ethernet_ipv4_tcp_frame(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = vec![0; 12];
        frame.extend_from_slice(&0x0800u16.to_be_bytes());
        frame.extend_from_slice(&ipv4_tcp_packet(
            source,
            destination,
            source_port,
            destination_port,
            sequence,
            payload,
        ));
        frame
    }

    fn ipv4_tcp_packet(
        source: [u8; 4],
        destination: [u8; 4],
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = 20 + 20 + payload.len();
        let mut packet = vec![0; 20 + 20];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet[20..22].copy_from_slice(&source_port.to_be_bytes());
        packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
        packet[24..28].copy_from_slice(&sequence.to_be_bytes());
        packet[32] = 5 << 4;
        packet[33] = 0x18;
        packet.extend_from_slice(payload);
        packet
    }
}
