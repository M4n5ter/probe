use std::{
    io, thread,
    time::{Duration, Instant},
};

use netlink_sys::{Socket as RawNetlinkSocket, SocketAddr, protocols::NETLINK_SOCK_DIAG};

use super::{
    SOCKET_DESTROY_TIMEOUT, SocketDestroyRequest,
    protocol::{
        InetDiagMessage, InetDiagRequest, NLM_F_ACK, NLM_F_DUMP, NLM_F_REQUEST, NetlinkError,
        NetlinkFrame, NetlinkPayloadFrame, SOCK_DESTROY, SOCK_DIAG_BY_FAMILY,
        encode_netlink_message, parse_netlink_messages,
    },
};

const NETLINK_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Debug)]
pub(super) struct NetlinkSocket {
    inner: RawNetlinkSocket,
}

impl NetlinkSocket {
    pub(super) fn connect_sock_diag() -> io::Result<Self> {
        let mut inner = RawNetlinkSocket::new(NETLINK_SOCK_DIAG)?;
        inner.bind_auto()?;
        inner.connect(&SocketAddr::new(0, 0))?;
        inner.set_non_blocking(true)?;
        Ok(Self { inner })
    }

    fn send(&mut self, bytes: &[u8]) -> io::Result<()> {
        let sent = self.inner.send(bytes, 0)?;
        if sent != bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!(
                    "short netlink send: wrote {} of {} bytes",
                    sent,
                    bytes.len()
                ),
            ));
        }
        Ok(())
    }

    fn recv(&mut self) -> io::Result<Vec<u8>> {
        let deadline = Instant::now() + SOCKET_DESTROY_TIMEOUT;
        let mut buffer = vec![0_u8; NETLINK_BUFFER_SIZE];
        loop {
            match self.inner.recv(&mut &mut buffer[..], 0) {
                Ok(received) => {
                    buffer.truncate(received);
                    return Ok(buffer);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "netlink SOCK_DESTROY timed out after {}ms",
                                SOCKET_DESTROY_TIMEOUT.as_millis()
                            ),
                        ));
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => return Err(error),
            }
        }
    }
}

pub(super) fn dump_matching_tcp_sockets(
    socket: &mut NetlinkSocket,
    request: &SocketDestroyRequest,
    sequence: u32,
) -> io::Result<Vec<InetDiagMessage>> {
    let query = InetDiagRequest::new(request.address_family()?, request.dump_socket_id());
    send_sock_diag_request(
        socket,
        SOCK_DIAG_BY_FAMILY,
        NLM_F_REQUEST | NLM_F_DUMP,
        sequence,
        query,
    )?;

    let mut responses = Vec::new();
    loop {
        for message in receive_netlink_messages(socket, sequence)? {
            match message.payload {
                NetlinkPayloadFrame::InetDiag(response) => {
                    if request.matches_response(&response) {
                        responses.push(response);
                    }
                }
                NetlinkPayloadFrame::Done => return Ok(responses),
                NetlinkPayloadFrame::Error(error) => return netlink_error_to_io(error),
                NetlinkPayloadFrame::Other => {}
            }
        }
    }
}

pub(super) fn destroy_tcp_socket(
    socket: &mut NetlinkSocket,
    response: &InetDiagMessage,
    sequence: u32,
) -> io::Result<()> {
    let request = InetDiagRequest::new(response.family, response.socket_id.clone());
    send_sock_diag_request(
        socket,
        SOCK_DESTROY,
        NLM_F_REQUEST | NLM_F_ACK,
        sequence,
        request,
    )?;

    loop {
        for message in receive_netlink_messages(socket, sequence)? {
            match message.payload {
                NetlinkPayloadFrame::Error(error) => return netlink_error_to_unit(error),
                NetlinkPayloadFrame::Done => return Ok(()),
                NetlinkPayloadFrame::InetDiag(_) | NetlinkPayloadFrame::Other => {}
            }
        }
    }
}

fn send_sock_diag_request(
    socket: &mut NetlinkSocket,
    message_type: u16,
    flags: u16,
    sequence: u32,
    request: InetDiagRequest,
) -> io::Result<()> {
    let payload = request.encode();
    let buffer = encode_netlink_message(message_type, flags, sequence, &payload);
    socket.send(&buffer)?;
    Ok(())
}

fn receive_netlink_messages(
    socket: &mut NetlinkSocket,
    sequence: u32,
) -> io::Result<Vec<NetlinkFrame>> {
    parse_netlink_messages(&socket.recv()?, sequence)
}

fn netlink_error_to_io<T>(error: NetlinkError) -> io::Result<T> {
    if error.code == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected netlink ACK in value-returning path",
        ));
    }
    Err(netlink_error_code_to_io(error.code))
}

fn netlink_error_to_unit(error: NetlinkError) -> io::Result<()> {
    if error.code == 0 {
        return Ok(());
    }
    Err(netlink_error_code_to_io(error.code))
}

fn netlink_error_code_to_io(raw: i32) -> io::Error {
    let errno = raw.checked_neg().unwrap_or(raw);
    if errno > 0 {
        io::Error::from_raw_os_error(errno)
    } else {
        io::Error::other(format!("netlink SOCK_DESTROY returned error code {raw}"))
    }
}
