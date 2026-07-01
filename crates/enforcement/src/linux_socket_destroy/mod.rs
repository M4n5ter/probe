mod capability;
mod protocol;
mod self_test;
mod transport;

use std::{io, net::IpAddr, time::Duration};

use probe_core::{TcpConnection, TcpEndpoint};

use self::protocol::{AF_INET, AF_INET6, InetDiagMessage, InetDiagSocketId};
use self::transport::{NetlinkSocket, destroy_tcp_socket, dump_matching_tcp_sockets};
pub use capability::{SocketDestroyCapabilityCheck, check_socket_destroy_capability};

const SOCKET_DESTROY_TIMEOUT: Duration = Duration::from_secs(2);

pub trait SocketDestroy {
    fn destroy(&mut self, request: &SocketDestroyRequest) -> io::Result<SocketDestroyOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SocketDestroyRequest {
    pub local_address: IpAddr,
    pub local_port: u16,
    pub remote_address: IpAddr,
    pub remote_port: u16,
}

impl SocketDestroyRequest {
    pub fn from_tcp_connection(connection: TcpConnection) -> Self {
        Self {
            local_address: connection.local.address,
            local_port: connection.local.port,
            remote_address: connection.remote.address,
            remote_port: connection.remote.port,
        }
    }

    pub fn tcp_connection(&self) -> TcpConnection {
        TcpConnection::new(
            TcpEndpoint::new(self.local_address, self.local_port),
            TcpEndpoint::new(self.remote_address, self.remote_port),
        )
    }

    fn address_family(&self) -> io::Result<u8> {
        match (self.local_address, self.remote_address) {
            (IpAddr::V4(_), IpAddr::V4(_)) => Ok(AF_INET),
            (IpAddr::V6(_), IpAddr::V6(_)) => Ok(AF_INET6),
            (local, remote) => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "socket destroy requires matching address families; local={local}, remote={remote}"
                ),
            )),
        }
    }

    fn dump_socket_id(&self) -> InetDiagSocketId {
        InetDiagSocketId {
            source_port: self.local_port,
            destination_port: self.remote_port,
            source_address: self.local_address,
            destination_address: self.remote_address,
            interface_id: 0,
            cookie: [0xff; 8],
        }
    }

    fn matches_response(&self, response: &InetDiagMessage) -> bool {
        let socket = &response.socket_id;
        socket.source_port == self.local_port
            && socket.destination_port == self.remote_port
            && socket.source_address == self.local_address
            && socket.destination_address == self.remote_address
    }
}

pub struct NetlinkSocketDestroy {
    next_sequence: u32,
}

impl NetlinkSocketDestroy {
    pub fn new() -> Self {
        Self { next_sequence: 1 }
    }

    fn allocate_sequence(&mut self) -> u32 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1).max(1);
        sequence
    }
}

impl Default for NetlinkSocketDestroy {
    fn default() -> Self {
        Self::new()
    }
}

impl SocketDestroy for NetlinkSocketDestroy {
    fn destroy(&mut self, request: &SocketDestroyRequest) -> io::Result<SocketDestroyOutcome> {
        let mut socket = NetlinkSocket::connect_sock_diag()?;
        let sockets = dump_matching_tcp_sockets(&mut socket, request, self.allocate_sequence())?;
        for response in &sockets {
            destroy_tcp_socket(&mut socket, response, self.allocate_sequence())?;
        }
        Ok(SocketDestroyOutcome::from_destroyed_socket_count(
            sockets.len(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocketDestroyOutcome {
    Destroyed { count: usize },
    NoMatchingSocket,
}

impl SocketDestroyOutcome {
    fn from_destroyed_socket_count(count: usize) -> Self {
        if count == 0 {
            Self::NoMatchingSocket
        } else {
            Self::Destroyed { count }
        }
    }
}

fn check_socket_destroy_prerequisites() -> Result<(), String> {
    NetlinkSocket::connect_sock_diag().map_err(|error| {
        format!("failed to open NETLINK_SOCK_DIAG socket for socket destroy: {error}")
    })?;
    Ok(())
}

fn check_loopback_socket_destroy_support() -> Result<(), String> {
    self_test::check_loopback_socket_destroy_support()
}

#[cfg(test)]
mod tests {
    use std::{
        io,
        net::{IpAddr, Ipv4Addr},
    };

    use super::*;

    #[test]
    fn socket_destroy_request_rejects_mixed_address_families() {
        let request = SocketDestroyRequest {
            local_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 41000,
            remote_address: "::1".parse().expect("IPv6 loopback"),
            remote_port: 8080,
        };

        assert_eq!(
            request.address_family().expect_err("mixed families").kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn socket_destroy_request_matches_only_exact_diag_response() {
        let request = SocketDestroyRequest {
            local_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            local_port: 41000,
            remote_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            remote_port: 8080,
        };
        let matching = InetDiagMessage {
            family: AF_INET,
            socket_id: request.dump_socket_id(),
        };
        let wrong_port = InetDiagMessage {
            family: AF_INET,
            socket_id: InetDiagSocketId {
                destination_port: 8081,
                ..request.dump_socket_id()
            },
        };

        assert!(request.matches_response(&matching));
        assert!(!request.matches_response(&wrong_port));
    }

    #[test]
    fn socket_destroy_outcome_reports_matching_socket_state() {
        assert_eq!(
            SocketDestroyOutcome::from_destroyed_socket_count(1),
            SocketDestroyOutcome::Destroyed { count: 1 }
        );
        assert_eq!(
            SocketDestroyOutcome::from_destroyed_socket_count(0),
            SocketDestroyOutcome::NoMatchingSocket
        );
    }
}
