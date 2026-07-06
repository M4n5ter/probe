use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pcap::Linktype;
use probe_core::TcpEndpoint;

use super::tcp_seq;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DecodedTcpSegment<'a> {
    pub(super) source: IpAddr,
    pub(super) destination: IpAddr,
    pub(super) source_port: u16,
    pub(super) destination_port: u16,
    pub(super) sequence: u32,
    pub(super) acknowledgment: u32,
    pub(super) flags: TcpFlags,
    pub(super) payload: &'a [u8],
}

impl<'a> DecodedTcpSegment<'a> {
    pub(super) fn decode(datalink: Linktype, frame: &'a [u8]) -> Option<Self> {
        match ip_packet(datalink, frame)? {
            IpPacket::V4(packet) => decode_ipv4_tcp_segment(packet),
            IpPacket::V6(packet) => decode_ipv6_tcp_segment(packet),
        }
    }

    pub(super) fn source_endpoint(&self) -> TcpEndpoint {
        TcpEndpoint::new(self.source, self.source_port)
    }

    pub(super) fn destination_endpoint(&self) -> TcpEndpoint {
        TcpEndpoint::new(self.destination, self.destination_port)
    }

    pub(super) fn has_lifecycle_signal(&self) -> bool {
        self.flags.syn || self.flags.fin || self.flags.rst
    }

    pub(super) fn has_syn(&self) -> bool {
        self.flags.syn
    }

    pub(super) fn has_syn_ack(&self) -> bool {
        self.flags.syn && self.flags.ack
    }

    pub(super) fn acknowledges_syn_sequence(&self, sequence: u32) -> bool {
        self.flags.ack && self.acknowledgment == tcp_seq::advance(sequence, 1)
    }

    pub(super) fn has_fin(&self) -> bool {
        self.flags.fin
    }

    pub(super) fn has_rst(&self) -> bool {
        self.flags.rst
    }

    pub(super) fn payload_sequence(&self) -> u32 {
        tcp_seq::advance(
            self.sequence,
            usize::from(self.flags.consumes_sequence_before_payload()),
        )
    }

    pub(super) fn close_sequence(&self) -> Option<u32> {
        (self.flags.fin || self.flags.rst)
            .then(|| tcp_seq::advance(self.payload_sequence(), self.payload.len()))
    }
}

enum IpPacket<'a> {
    V4(&'a [u8]),
    V6(&'a [u8]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TcpFlags {
    pub(super) syn: bool,
    pub(super) ack: bool,
    pub(super) fin: bool,
    pub(super) rst: bool,
}

impl TcpFlags {
    fn from_byte(flags: u8) -> Self {
        Self {
            syn: flags & 0x02 != 0,
            ack: flags & 0x10 != 0,
            fin: flags & 0x01 != 0,
            rst: flags & 0x04 != 0,
        }
    }

    fn consumes_sequence_before_payload(&self) -> bool {
        self.syn
    }
}

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_8021Q: u16 = 0x8100;
const ETHERTYPE_IPV6: u16 = 0x86dd;
const ETHERTYPE_8021AD: u16 = 0x88a8;
const ETHERTYPE_9100: u16 = 0x9100;
const IPPROTO_TCP: u8 = 6;
const IPV4_MIN_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const TCP_MIN_HEADER_LEN: usize = 20;
const LOOPBACK_AF_INET: u32 = 2;
const LOOPBACK_AF_INET6_LINUX: u32 = 10;
const LOOPBACK_AF_INET6_NETBSD_OPENBSD: u32 = 24;
const LOOPBACK_AF_INET6_FREEBSD: u32 = 28;
const LOOPBACK_AF_INET6_DARWIN: u32 = 30;

fn ip_packet(datalink: Linktype, frame: &[u8]) -> Option<IpPacket<'_>> {
    match datalink {
        Linktype::ETHERNET => ethernet_ip_packet(frame),
        Linktype::LINUX_SLL => linux_sll_ip_packet(frame),
        Linktype::LINUX_SLL2 => linux_sll2_ip_packet(frame),
        Linktype::RAW => raw_ip_packet(frame),
        Linktype::IPV4 => Some(IpPacket::V4(frame)),
        Linktype::IPV6 => Some(IpPacket::V6(frame)),
        Linktype::NULL | Linktype::LOOP => loopback_ip_packet(frame),
        _ => None,
    }
}

fn ethernet_ip_packet(frame: &[u8]) -> Option<IpPacket<'_>> {
    if frame.len() < 14 {
        return None;
    }
    let mut offset = 14;
    let mut ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    while matches!(
        ethertype,
        ETHERTYPE_8021Q | ETHERTYPE_8021AD | ETHERTYPE_9100
    ) {
        if frame.len() < offset + 4 {
            return None;
        }
        ethertype = u16::from_be_bytes([frame[offset + 2], frame[offset + 3]]);
        offset += 4;
    }
    ip_packet_from_ethertype(ethertype, &frame[offset..])
}

fn linux_sll_ip_packet(frame: &[u8]) -> Option<IpPacket<'_>> {
    if frame.len() < 16 {
        return None;
    }
    let protocol = u16::from_be_bytes([frame[14], frame[15]]);
    ip_packet_from_ethertype(protocol, &frame[16..])
}

fn linux_sll2_ip_packet(frame: &[u8]) -> Option<IpPacket<'_>> {
    if frame.len() < 20 {
        return None;
    }
    let protocol = u16::from_be_bytes([frame[0], frame[1]]);
    ip_packet_from_ethertype(protocol, &frame[20..])
}

fn loopback_ip_packet(frame: &[u8]) -> Option<IpPacket<'_>> {
    if frame.len() < 4 {
        return None;
    }
    let family_ne = u32::from_ne_bytes([frame[0], frame[1], frame[2], frame[3]]);
    let family_be = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if family_ne == LOOPBACK_AF_INET || family_be == LOOPBACK_AF_INET {
        Some(IpPacket::V4(&frame[4..]))
    } else if loopback_family_is_ipv6(family_ne) || loopback_family_is_ipv6(family_be) {
        Some(IpPacket::V6(&frame[4..]))
    } else {
        None
    }
}

fn ip_packet_from_ethertype(ethertype: u16, packet: &[u8]) -> Option<IpPacket<'_>> {
    match ethertype {
        ETHERTYPE_IPV4 => Some(IpPacket::V4(packet)),
        ETHERTYPE_IPV6 => Some(IpPacket::V6(packet)),
        _ => None,
    }
}

fn raw_ip_packet(packet: &[u8]) -> Option<IpPacket<'_>> {
    match packet.first()? >> 4 {
        4 => Some(IpPacket::V4(packet)),
        6 => Some(IpPacket::V6(packet)),
        _ => None,
    }
}

fn loopback_family_is_ipv6(family: u32) -> bool {
    matches!(
        family,
        LOOPBACK_AF_INET6_LINUX
            | LOOPBACK_AF_INET6_NETBSD_OPENBSD
            | LOOPBACK_AF_INET6_FREEBSD
            | LOOPBACK_AF_INET6_DARWIN
    )
}

fn decode_ipv4_tcp_segment(packet: &[u8]) -> Option<DecodedTcpSegment<'_>> {
    if packet.len() < IPV4_MIN_HEADER_LEN || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_MIN_HEADER_LEN || packet.len() < header_len || packet[9] != IPPROTO_TCP {
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
    let source = IpAddr::V4(Ipv4Addr::new(
        packet[12], packet[13], packet[14], packet[15],
    ));
    let destination = IpAddr::V4(Ipv4Addr::new(
        packet[16], packet[17], packet[18], packet[19],
    ));
    decode_tcp_segment(source, destination, tcp)
}

fn decode_ipv6_tcp_segment(packet: &[u8]) -> Option<DecodedTcpSegment<'_>> {
    if packet.len() < IPV6_HEADER_LEN || packet[0] >> 4 != 6 {
        return None;
    }
    if packet[6] != IPPROTO_TCP {
        return None;
    }
    let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
    let total_len = IPV6_HEADER_LEN.checked_add(payload_len)?;
    if packet.len() < total_len {
        return None;
    }
    let tcp = &packet[IPV6_HEADER_LEN..total_len];
    let source = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?));
    let destination = IpAddr::V6(Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?));
    decode_tcp_segment(source, destination, tcp)
}

fn decode_tcp_segment(
    source: IpAddr,
    destination: IpAddr,
    tcp: &[u8],
) -> Option<DecodedTcpSegment<'_>> {
    if tcp.len() < TCP_MIN_HEADER_LEN {
        return None;
    }
    let tcp_header_len = usize::from(tcp[12] >> 4) * 4;
    if tcp_header_len < TCP_MIN_HEADER_LEN || tcp.len() < tcp_header_len {
        return None;
    }
    let payload = &tcp[tcp_header_len..];
    Some(DecodedTcpSegment {
        source,
        destination,
        source_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        destination_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        acknowledgment: u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]),
        flags: TcpFlags::from_byte(tcp[13]),
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_and_close_sequences_account_for_tcp_control_bytes() {
        let syn_data_fin = DecodedTcpSegment {
            source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            destination: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            source_port: 50_000,
            destination_port: 80,
            sequence: 41,
            acknowledgment: 0,
            flags: TcpFlags {
                syn: true,
                ack: true,
                fin: true,
                rst: false,
            },
            payload: b"hi",
        };
        let pure_fin = DecodedTcpSegment {
            sequence: 108,
            acknowledgment: 0,
            flags: TcpFlags {
                syn: false,
                ack: true,
                fin: true,
                rst: false,
            },
            payload: b"",
            ..syn_data_fin
        };

        assert_eq!(syn_data_fin.payload_sequence(), 42);
        assert_eq!(syn_data_fin.close_sequence(), Some(44));
        assert_eq!(pure_fin.payload_sequence(), 108);
        assert_eq!(pure_fin.close_sequence(), Some(108));
    }

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
            DecodedTcpSegment::decode(Linktype::ETHERNET, &frame).expect("expected tcp payload");

        assert_eq!(decoded.source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(decoded.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(decoded.source_port, 50_000);
        assert_eq!(decoded.destination_port, 80);
        assert_eq!(decoded.sequence, 100);
        assert_eq!(decoded.payload, b"GET / HTTP/1.1\r\n\r\n");
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
            DecodedTcpSegment::decode(Linktype::LINUX_SLL, &frame).expect("expected tcp payload");

        assert_eq!(decoded.source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(decoded.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            decoded.payload,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        );
    }

    #[test]
    fn decodes_linux_sll2_ipv6_tcp_http_request_payload() {
        let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut frame = vec![0; 20];
        frame[0..2].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        frame.extend_from_slice(&ipv6_tcp_packet(
            source,
            destination,
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        ));

        let decoded =
            DecodedTcpSegment::decode(Linktype::LINUX_SLL2, &frame).expect("expected tcp payload");

        assert_eq!(decoded.source, IpAddr::V6(Ipv6Addr::from(source)));
        assert_eq!(decoded.destination, IpAddr::V6(Ipv6Addr::from(destination)));
        assert_eq!(decoded.payload, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn decodes_ethernet_ipv6_tcp_http_request_payload() {
        let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let frame = ethernet_ipv6_tcp_frame(
            source,
            destination,
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        );

        let decoded =
            DecodedTcpSegment::decode(Linktype::ETHERNET, &frame).expect("expected tcp payload");

        assert_eq!(decoded.source, IpAddr::V6(Ipv6Addr::from(source)));
        assert_eq!(decoded.destination, IpAddr::V6(Ipv6Addr::from(destination)));
        assert_eq!(decoded.source_port, 50_000);
        assert_eq!(decoded.destination_port, 80);
        assert_eq!(decoded.sequence, 100);
        assert_eq!(decoded.payload, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn decodes_vlan_ethernet_ipv4_tcp_http_request_payload() {
        let mut frame = vec![0; 12];
        frame.extend_from_slice(&ETHERTYPE_8021Q.to_be_bytes());
        frame.extend_from_slice(&100u16.to_be_bytes());
        frame.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
        frame.extend_from_slice(&ipv4_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        ));

        let decoded =
            DecodedTcpSegment::decode(Linktype::ETHERNET, &frame).expect("expected tcp payload");

        assert_eq!(decoded.source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(decoded.destination, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(decoded.payload, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn decodes_loopback_ipv6_tcp_http_request_payload() {
        let source = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let mut frame = 10u32.to_ne_bytes().to_vec();
        frame.extend_from_slice(&ipv6_tcp_packet(
            source,
            destination,
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        ));

        let decoded =
            DecodedTcpSegment::decode(Linktype::LOOP, &frame).expect("expected tcp payload");

        assert_eq!(decoded.source, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(decoded.destination, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(decoded.payload, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn decodes_loopback_big_endian_ipv4_tcp_http_request_payload() {
        let mut frame = LOOPBACK_AF_INET.to_be_bytes().to_vec();
        frame.extend_from_slice(&ipv4_tcp_packet(
            [127, 0, 0, 1],
            [127, 0, 0, 1],
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        ));

        let decoded =
            DecodedTcpSegment::decode(Linktype::NULL, &frame).expect("expected tcp payload");

        assert_eq!(decoded.source, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(decoded.destination, IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(decoded.payload, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[test]
    fn decodes_raw_and_direct_ip_tcp_http_request_payload() {
        let ipv4_packet = ipv4_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        let decoded_ipv4 =
            DecodedTcpSegment::decode(Linktype::RAW, &ipv4_packet).expect("expected tcp payload");
        assert_eq!(decoded_ipv4.source, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(decoded_ipv4.payload, b"GET / HTTP/1.1\r\n\r\n");

        let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let ipv6_packet = ipv6_tcp_packet(
            source,
            destination,
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        let decoded_ipv6 =
            DecodedTcpSegment::decode(Linktype::IPV6, &ipv6_packet).expect("expected tcp payload");
        assert_eq!(decoded_ipv6.source, IpAddr::V6(Ipv6Addr::from(source)));
        assert_eq!(decoded_ipv6.payload, b"GET / HTTP/1.1\r\n\r\n");
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
        assert!(DecodedTcpSegment::decode(Linktype::IPV4, &fragment).is_none());

        let mut truncated = ipv4_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        truncated.truncate(truncated.len() - 1);
        assert!(DecodedTcpSegment::decode(Linktype::IPV4, &truncated).is_none());
    }

    #[test]
    fn skips_ipv6_extension_or_truncated_packets() {
        let source = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let destination = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut extension = ipv6_tcp_packet(
            source,
            destination,
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        extension[6] = 44;
        assert!(DecodedTcpSegment::decode(Linktype::IPV6, &extension).is_none());

        let mut truncated = ipv6_tcp_packet(
            source,
            destination,
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        truncated.truncate(truncated.len() - 1);
        assert!(DecodedTcpSegment::decode(Linktype::IPV6, &truncated).is_none());
    }

    #[test]
    fn decodes_empty_fin_segment_for_flow_lifecycle() {
        let mut packet = ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50_000, 80, 100, b"");
        packet[33] = 0x11;

        let decoded =
            DecodedTcpSegment::decode(Linktype::IPV4, &packet).expect("expected tcp fin segment");

        assert!(decoded.payload.is_empty());
        assert!(decoded.has_fin());
    }

    #[test]
    fn decodes_empty_syn_segment_for_flow_lifecycle() {
        let mut packet = ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50_000, 80, 100, b"");
        packet[33] = 0x02;

        let decoded =
            DecodedTcpSegment::decode(Linktype::IPV4, &packet).expect("expected tcp syn segment");

        assert!(decoded.payload.is_empty());
        assert!(decoded.has_syn());
        assert!(decoded.has_lifecycle_signal());
    }

    #[test]
    fn decodes_empty_syn_ack_segment_for_flow_lifecycle() {
        let mut packet = ipv4_tcp_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 50_000, 200, b"");
        packet[28..32].copy_from_slice(&101u32.to_be_bytes());
        packet[33] = 0x12;

        let decoded = DecodedTcpSegment::decode(Linktype::IPV4, &packet)
            .expect("expected tcp syn-ack segment");

        assert!(decoded.payload.is_empty());
        assert!(decoded.has_syn());
        assert!(decoded.has_syn_ack());
        assert_eq!(decoded.acknowledgment, 101);
        assert!(decoded.acknowledges_syn_sequence(100));
        assert!(decoded.has_lifecycle_signal());
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

    fn ethernet_ipv6_tcp_frame(
        source: [u8; 16],
        destination: [u8; 16],
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame = vec![0; 12];
        frame.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        frame.extend_from_slice(&ipv6_tcp_packet(
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

    fn ipv6_tcp_packet(
        source: [u8; 16],
        destination: [u8; 16],
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let payload_len = 20 + payload.len();
        let mut packet = vec![0; 40 + 20];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source);
        packet[24..40].copy_from_slice(&destination);
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..48].copy_from_slice(&sequence.to_be_bytes());
        packet[52] = 5 << 4;
        packet[53] = 0x18;
        packet.extend_from_slice(payload);
        packet
    }
}
