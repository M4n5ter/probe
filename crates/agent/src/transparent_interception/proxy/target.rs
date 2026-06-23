use std::net::SocketAddr;

use socket2::Socket;

use super::{proxy_error, proxy_io_error};
use crate::transparent_interception::TransparentInterceptionError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TransparentProxyTargetRecovery {
    TproxyLocalAddress,
    LinuxOriginalDestination,
}

impl TransparentProxyTargetRecovery {
    pub(in crate::transparent_interception::proxy) fn description(self) -> &'static str {
        match self {
            Self::TproxyLocalAddress => "TPROXY accepted-socket local address",
            Self::LinuxOriginalDestination => "Linux original-destination resolver",
        }
    }

    pub(super) fn recover(
        self,
        socket: &Socket,
    ) -> Result<SocketAddr, TransparentInterceptionError> {
        match self {
            Self::TproxyLocalAddress => tproxy_local_address(socket),
            Self::LinuxOriginalDestination => linux_original_destination(socket),
        }
    }
}

fn tproxy_local_address(socket: &Socket) -> Result<SocketAddr, TransparentInterceptionError> {
    socket
        .local_addr()
        .map_err(proxy_io_error("read transparent socket local address"))?
        .as_socket()
        .ok_or_else(|| proxy_error("transparent socket local address is not an IP socket"))
}

fn linux_original_destination(socket: &Socket) -> Result<SocketAddr, TransparentInterceptionError> {
    let local_address = tproxy_local_address(socket)?;
    let original_destination = match local_address {
        SocketAddr::V4(_) => socket
            .original_dst_v4()
            .map_err(proxy_io_error("read IPv4 Linux original destination"))?,
        SocketAddr::V6(_) => socket
            .original_dst_v6()
            .map_err(proxy_io_error("read IPv6 Linux original destination"))?,
    };
    original_destination
        .as_socket()
        .ok_or_else(|| proxy_error("Linux original destination is not an IP socket"))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, TcpListener, TcpStream};

    use socket2::Socket;

    use super::*;

    #[test]
    fn tproxy_local_address_uses_accepted_socket_local_addr()
    -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let expected_target = listener.local_addr()?;
        let client = TcpStream::connect(expected_target)?;
        let (accepted, _) = listener.accept()?;

        let target =
            TransparentProxyTargetRecovery::TproxyLocalAddress.recover(&Socket::from(accepted))?;

        assert_eq!(target, expected_target);
        drop(client);
        Ok(())
    }
}
