use std::net::{IpAddr, Ipv4Addr};

use pcap::Linktype;
use probe_core::TcpEndpoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct DecodedTcpSegment<'a> {
    pub(super) source: Ipv4Addr,
    pub(super) destination: Ipv4Addr,
    pub(super) source_port: u16,
    pub(super) destination_port: u16,
    pub(super) sequence: u32,
    pub(super) flags: TcpFlags,
    pub(super) payload: &'a [u8],
}

impl<'a> DecodedTcpSegment<'a> {
    pub(super) fn decode(datalink: Linktype, frame: &'a [u8]) -> Option<Self> {
        let ipv4 = ipv4_payload(datalink, frame)?;
        decode_ipv4_tcp_segment(ipv4)
    }

    pub(super) fn source_endpoint(&self) -> TcpEndpoint {
        TcpEndpoint::new(IpAddr::V4(self.source), self.source_port)
    }

    pub(super) fn destination_endpoint(&self) -> TcpEndpoint {
        TcpEndpoint::new(IpAddr::V4(self.destination), self.destination_port)
    }

    pub(super) fn has_lifecycle_signal(&self) -> bool {
        self.flags.syn || self.flags.fin || self.flags.rst
    }

    pub(super) fn has_syn(&self) -> bool {
        self.flags.syn
    }

    pub(super) fn has_fin(&self) -> bool {
        self.flags.fin
    }

    pub(super) fn has_rst(&self) -> bool {
        self.flags.rst
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct TcpFlags {
    pub(super) syn: bool,
    pub(super) fin: bool,
    pub(super) rst: bool,
}

impl TcpFlags {
    fn from_byte(flags: u8) -> Self {
        Self {
            syn: flags & 0x02 != 0,
            fin: flags & 0x01 != 0,
            rst: flags & 0x04 != 0,
        }
    }
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

fn decode_ipv4_tcp_segment(packet: &[u8]) -> Option<DecodedTcpSegment<'_>> {
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
    Some(DecodedTcpSegment {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        source_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        destination_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        sequence: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
        flags: TcpFlags::from_byte(tcp[13]),
        payload,
    })
}

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
            DecodedTcpSegment::decode(Linktype::ETHERNET, &frame).expect("expected tcp payload");

        assert_eq!(decoded.source, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(decoded.destination, Ipv4Addr::new(10, 0, 0, 2));
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

        assert_eq!(decoded.source, Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(decoded.destination, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            decoded.payload,
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        );
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
        assert!(decode_ipv4_tcp_segment(&fragment).is_none());

        let mut truncated = ipv4_tcp_packet(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            50_000,
            80,
            100,
            b"GET / HTTP/1.1\r\n\r\n",
        );
        truncated.truncate(truncated.len() - 1);
        assert!(decode_ipv4_tcp_segment(&truncated).is_none());
    }

    #[test]
    fn decodes_empty_fin_segment_for_flow_lifecycle() {
        let mut packet = ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50_000, 80, 100, b"");
        packet[33] = 0x11;

        let decoded = decode_ipv4_tcp_segment(&packet).expect("expected tcp fin segment");

        assert!(decoded.payload.is_empty());
        assert!(decoded.has_fin());
    }

    #[test]
    fn decodes_empty_syn_segment_for_flow_lifecycle() {
        let mut packet = ipv4_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 50_000, 80, 100, b"");
        packet[33] = 0x02;

        let decoded = decode_ipv4_tcp_segment(&packet).expect("expected tcp syn segment");

        assert!(decoded.payload.is_empty());
        assert!(decoded.has_syn());
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
