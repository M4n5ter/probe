use std::{
    io,
    net::{IpAddr, Ipv4Addr},
};

pub(super) const NETLINK_HEADER_LEN: usize = 16;
const NETLINK_ALIGN_TO: usize = 4;
pub(super) const SOCK_DIAG_BY_FAMILY: u16 = 20;
pub(super) const SOCK_DESTROY: u16 = 21;
pub(super) const NLMSG_ERROR: u16 = 2;
pub(super) const NLMSG_DONE: u16 = 3;
pub(super) const NLM_F_REQUEST: u16 = 0x01;
pub(super) const NLM_F_ACK: u16 = 0x04;
pub(super) const NLM_F_DUMP: u16 = 0x300;
pub(super) const AF_INET: u8 = libc::AF_INET as u8;
pub(super) const AF_INET6: u8 = libc::AF_INET6 as u8;
pub(super) const IPPROTO_TCP: u8 = libc::IPPROTO_TCP as u8;
const TCP_ESTABLISHED: u32 = 1;
const TCP_SYN_SENT: u32 = 2;
const TCP_SYN_RECV: u32 = 3;
const TCP_FIN_WAIT1: u32 = 4;
const TCP_FIN_WAIT2: u32 = 5;
const TCP_TIME_WAIT: u32 = 6;
const TCP_CLOSE_WAIT: u32 = 8;
const TCP_LAST_ACK: u32 = 9;
const TCP_CLOSING: u32 = 11;
pub(super) const TCPF_CONNECTED: u32 = (1 << TCP_ESTABLISHED)
    | (1 << TCP_SYN_SENT)
    | (1 << TCP_SYN_RECV)
    | (1 << TCP_FIN_WAIT1)
    | (1 << TCP_FIN_WAIT2)
    | (1 << TCP_TIME_WAIT)
    | (1 << TCP_CLOSE_WAIT)
    | (1 << TCP_LAST_ACK)
    | (1 << TCP_CLOSING);
pub(super) const INET_DIAG_REQUEST_LEN: usize = 56;
pub(super) const INET_DIAG_MESSAGE_LEN: usize = 72;
const INET_DIAG_SOCKET_ID_LEN: usize = 48;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InetDiagRequest {
    family: u8,
    protocol: u8,
    states: u32,
    socket_id: InetDiagSocketId,
}

impl InetDiagRequest {
    pub(super) fn new(family: u8, socket_id: InetDiagSocketId) -> Self {
        Self {
            family,
            protocol: IPPROTO_TCP,
            states: TCPF_CONNECTED,
            socket_id,
        }
    }

    pub(super) fn encode(&self) -> [u8; INET_DIAG_REQUEST_LEN] {
        let mut bytes = [0_u8; INET_DIAG_REQUEST_LEN];
        bytes[0] = self.family;
        bytes[1] = self.protocol;
        bytes[4..8].copy_from_slice(&self.states.to_ne_bytes());
        self.socket_id.encode_into(&mut bytes[8..56]);
        bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InetDiagMessage {
    pub(super) family: u8,
    pub(super) socket_id: InetDiagSocketId,
}

impl InetDiagMessage {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < INET_DIAG_MESSAGE_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "short inet_diag_msg: expected at least {INET_DIAG_MESSAGE_LEN} bytes, got {}",
                    bytes.len()
                ),
            ));
        }
        let family = bytes[0];
        Ok(Self {
            family,
            socket_id: InetDiagSocketId::parse(family, &bytes[4..52])?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct InetDiagSocketId {
    pub(super) source_port: u16,
    pub(super) destination_port: u16,
    pub(super) source_address: IpAddr,
    pub(super) destination_address: IpAddr,
    pub(super) interface_id: u32,
    pub(super) cookie: [u8; 8],
}

impl InetDiagSocketId {
    fn encode_into(&self, bytes: &mut [u8]) {
        debug_assert_eq!(bytes.len(), INET_DIAG_SOCKET_ID_LEN);
        bytes[0..2].copy_from_slice(&self.source_port.to_be_bytes());
        bytes[2..4].copy_from_slice(&self.destination_port.to_be_bytes());
        encode_diag_address(self.source_address, &mut bytes[4..20]);
        encode_diag_address(self.destination_address, &mut bytes[20..36]);
        bytes[36..40].copy_from_slice(&self.interface_id.to_ne_bytes());
        bytes[40..48].copy_from_slice(&self.cookie);
    }

    fn parse(family: u8, bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < INET_DIAG_SOCKET_ID_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "short inet_diag_sockid: expected {INET_DIAG_SOCKET_ID_LEN} bytes, got {}",
                    bytes.len()
                ),
            ));
        }
        let source_address = parse_diag_address(family, &bytes[4..20])?;
        let destination_address = parse_diag_address(family, &bytes[20..36])?;
        let mut cookie = [0_u8; 8];
        cookie.copy_from_slice(&bytes[40..48]);
        Ok(Self {
            source_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            destination_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            source_address,
            destination_address,
            interface_id: u32::from_ne_bytes(bytes[36..40].try_into().expect("u32 slice")),
            cookie,
        })
    }
}

fn encode_diag_address(address: IpAddr, bytes: &mut [u8]) {
    debug_assert_eq!(bytes.len(), 16);
    bytes.fill(0);
    match address {
        IpAddr::V4(address) => bytes[..4].copy_from_slice(&address.octets()),
        IpAddr::V6(address) => bytes.copy_from_slice(&address.octets()),
    }
}

fn parse_diag_address(family: u8, bytes: &[u8]) -> io::Result<IpAddr> {
    match family {
        AF_INET => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        AF_INET6 => {
            let octets: [u8; 16] = bytes.try_into().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid IPv6 address length")
            })?;
            Ok(IpAddr::V6(octets.into()))
        }
        family => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported inet_diag address family {family}"),
        )),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NetlinkFrame {
    pub(super) payload: NetlinkPayloadFrame,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NetlinkPayloadFrame {
    Done,
    Error(NetlinkError),
    InetDiag(InetDiagMessage),
    Other,
}

impl NetlinkPayloadFrame {
    fn parse(message_type: u16, payload: &[u8]) -> io::Result<Self> {
        match message_type {
            NLMSG_DONE => Ok(Self::Done),
            NLMSG_ERROR => Ok(Self::Error(NetlinkError::parse(payload)?)),
            SOCK_DIAG_BY_FAMILY => Ok(Self::InetDiag(InetDiagMessage::parse(payload)?)),
            _ => Ok(Self::Other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct NetlinkError {
    pub(super) code: i32,
}

impl NetlinkError {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < 4 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("short netlink error payload: got {} bytes", bytes.len()),
            ));
        }
        Ok(Self {
            code: i32::from_ne_bytes(bytes[0..4].try_into().expect("i32 slice")),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NetlinkFrameHeader {
    length: u32,
    message_type: u16,
    sequence: u32,
}

impl NetlinkFrameHeader {
    fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < NETLINK_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "short netlink header: expected {NETLINK_HEADER_LEN} bytes, got {}",
                    bytes.len()
                ),
            ));
        }
        Ok(Self {
            length: u32::from_ne_bytes(bytes[0..4].try_into().expect("u32 slice")),
            message_type: u16::from_ne_bytes(bytes[4..6].try_into().expect("u16 slice")),
            sequence: u32::from_ne_bytes(bytes[8..12].try_into().expect("u32 slice")),
        })
    }
}

pub(super) fn encode_netlink_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    payload: &[u8],
) -> Vec<u8> {
    let length = NETLINK_HEADER_LEN + payload.len();
    let mut bytes = Vec::with_capacity(align_netlink_message_len(length));
    bytes.extend_from_slice(&(length as u32).to_ne_bytes());
    bytes.extend_from_slice(&message_type.to_ne_bytes());
    bytes.extend_from_slice(&flags.to_ne_bytes());
    bytes.extend_from_slice(&sequence.to_ne_bytes());
    bytes.extend_from_slice(&0_u32.to_ne_bytes());
    bytes.extend_from_slice(payload);
    bytes.resize(align_netlink_message_len(length), 0);
    bytes
}

pub(super) fn parse_netlink_messages(
    mut bytes: &[u8],
    sequence: u32,
) -> io::Result<Vec<NetlinkFrame>> {
    let mut messages = Vec::new();
    while bytes.len() >= NETLINK_HEADER_LEN {
        let header = NetlinkFrameHeader::parse(bytes)?;
        let message_len = header.length as usize;
        if message_len < NETLINK_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid netlink message length {message_len}"),
            ));
        }
        let aligned_len = align_netlink_message_len(message_len);
        if aligned_len > bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "netlink message length {message_len} exceeds received datagram length {}",
                    bytes.len()
                ),
            ));
        }
        if header.sequence == sequence {
            let payload = &bytes[NETLINK_HEADER_LEN..message_len];
            messages.push(NetlinkFrame {
                payload: NetlinkPayloadFrame::parse(header.message_type, payload)?,
            });
        }
        bytes = &bytes[aligned_len..];
    }
    Ok(messages)
}

fn align_netlink_message_len(len: usize) -> usize {
    (len + NETLINK_ALIGN_TO - 1) & !(NETLINK_ALIGN_TO - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inet_diag_request_encodes_ipv4_socket_id() {
        let socket_id = InetDiagSocketId {
            source_port: 41000,
            destination_port: 8080,
            source_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            destination_address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            interface_id: 0,
            cookie: [0xff; 8],
        };
        let encoded = InetDiagRequest::new(AF_INET, socket_id).encode();

        assert_eq!(encoded.len(), INET_DIAG_REQUEST_LEN);
        assert_eq!(encoded[0], AF_INET);
        assert_eq!(encoded[1], IPPROTO_TCP);
        assert_eq!(
            u32::from_ne_bytes(encoded[4..8].try_into().expect("state bytes")),
            TCPF_CONNECTED
        );
        assert_eq!(&encoded[8..10], &41000_u16.to_be_bytes());
        assert_eq!(&encoded[10..12], &8080_u16.to_be_bytes());
        assert_eq!(&encoded[12..16], &[127, 0, 0, 1]);
        assert_eq!(&encoded[16..28], &[0; 12]);
        assert_eq!(&encoded[28..32], &[127, 0, 0, 1]);
        assert_eq!(&encoded[32..44], &[0; 12]);
        assert_eq!(&encoded[48..56], &[0xff; 8]);
    }

    #[test]
    fn inet_diag_request_encodes_ipv6_socket_id() {
        let local = "2001:db8::1".parse::<IpAddr>().expect("local IPv6");
        let remote = "2001:db8::2".parse::<IpAddr>().expect("remote IPv6");
        let socket_id = InetDiagSocketId {
            source_port: 41000,
            destination_port: 8080,
            source_address: local,
            destination_address: remote,
            interface_id: 0,
            cookie: [0xff; 8],
        };
        let encoded = InetDiagRequest::new(AF_INET6, socket_id).encode();

        assert_eq!(encoded[0], AF_INET6);
        assert_eq!(&encoded[12..28], &local_octets(local));
        assert_eq!(&encoded[28..44], &local_octets(remote));
    }

    #[test]
    fn netlink_message_encoding_sets_header_length_and_alignment() {
        let encoded =
            encode_netlink_message(SOCK_DESTROY, NLM_F_REQUEST | NLM_F_ACK, 7, &[1, 2, 3]);

        assert_eq!(encoded.len(), 20);
        assert_eq!(
            u32::from_ne_bytes(encoded[0..4].try_into().expect("length")),
            19
        );
        assert_eq!(
            u16::from_ne_bytes(encoded[4..6].try_into().expect("type")),
            SOCK_DESTROY
        );
        assert_eq!(
            u16::from_ne_bytes(encoded[6..8].try_into().expect("flags")),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(
            u32::from_ne_bytes(encoded[8..12].try_into().expect("sequence")),
            7
        );
        assert_eq!(&encoded[16..19], &[1, 2, 3]);
        assert_eq!(encoded[19], 0);
    }

    #[test]
    fn parse_netlink_messages_filters_sequence_and_parses_inet_diag_response() {
        let socket_id = InetDiagSocketId {
            source_port: 41000,
            destination_port: 8080,
            source_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            interface_id: 3,
            cookie: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        let payload = inet_diag_message_payload(AF_INET, &socket_id);
        let mut datagram = encode_netlink_message(SOCK_DIAG_BY_FAMILY, 0, 11, &payload);
        datagram.extend_from_slice(&encode_netlink_message(
            SOCK_DIAG_BY_FAMILY,
            0,
            12,
            &payload,
        ));

        let parsed = parse_netlink_messages(&datagram, 11).expect("parse datagram");

        assert_eq!(
            parsed,
            vec![NetlinkFrame {
                payload: NetlinkPayloadFrame::InetDiag(InetDiagMessage {
                    family: AF_INET,
                    socket_id,
                }),
            }]
        );
    }

    #[test]
    fn parse_netlink_messages_parses_ack_and_error() {
        let ack = encode_netlink_message(NLMSG_ERROR, 0, 9, &0_i32.to_ne_bytes());
        let error = encode_netlink_message(NLMSG_ERROR, 0, 10, &(-libc::EPERM).to_ne_bytes());

        assert_eq!(
            parse_netlink_messages(&ack, 9).expect("parse ack"),
            vec![NetlinkFrame {
                payload: NetlinkPayloadFrame::Error(NetlinkError { code: 0 }),
            }]
        );
        assert_eq!(
            parse_netlink_messages(&error, 10).expect("parse error"),
            vec![NetlinkFrame {
                payload: NetlinkPayloadFrame::Error(NetlinkError { code: -libc::EPERM }),
            }]
        );
    }

    #[test]
    fn connected_state_mask_excludes_closed_and_listening_states() {
        const TCP_CLOSE: u32 = 7;
        const TCP_LISTEN: u32 = 10;

        for state in [
            TCP_ESTABLISHED,
            TCP_SYN_SENT,
            TCP_SYN_RECV,
            TCP_FIN_WAIT1,
            TCP_FIN_WAIT2,
            TCP_TIME_WAIT,
            TCP_CLOSE_WAIT,
            TCP_LAST_ACK,
            TCP_CLOSING,
        ] {
            assert_ne!(TCPF_CONNECTED & (1 << state), 0);
        }
        assert_eq!(TCPF_CONNECTED & (1 << TCP_CLOSE), 0);
        assert_eq!(TCPF_CONNECTED & (1 << TCP_LISTEN), 0);
    }

    fn inet_diag_message_payload(
        family: u8,
        socket_id: &InetDiagSocketId,
    ) -> [u8; INET_DIAG_MESSAGE_LEN] {
        let mut payload = [0_u8; INET_DIAG_MESSAGE_LEN];
        payload[0] = family;
        socket_id.encode_into(&mut payload[4..52]);
        payload
    }

    fn local_octets(address: IpAddr) -> [u8; 16] {
        match address {
            IpAddr::V6(address) => address.octets(),
            IpAddr::V4(_) => panic!("expected IPv6 address"),
        }
    }
}
