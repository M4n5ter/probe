use std::{
    io,
    net::{SocketAddr, TcpStream},
    num::NonZeroU32,
    time::Duration,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

#[derive(Clone, Copy, Debug)]
pub(super) struct TransparentProxyUpstreamConnectPlan {
    timeout: Duration,
    proxy_bypass_mark: Option<TransparentProxyBypassMark>,
}

impl TransparentProxyUpstreamConnectPlan {
    pub(super) fn new(
        timeout: Duration,
        proxy_bypass_mark: Option<TransparentProxyBypassMark>,
    ) -> Self {
        Self {
            timeout,
            proxy_bypass_mark,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct TransparentProxyBypassMark(pub(super) NonZeroU32);

impl TransparentProxyBypassMark {
    pub(super) fn new(mark: NonZeroU32) -> Self {
        Self(mark)
    }

    fn get(self) -> u32 {
        self.0.get()
    }
}

pub(super) fn connect_tcp(
    target: SocketAddr,
    plan: TransparentProxyUpstreamConnectPlan,
) -> io::Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if let Some(mark) = plan.proxy_bypass_mark {
        socket.set_mark(mark.get())?;
    }
    socket.connect_timeout(&SockAddr::from(target), plan.timeout)?;
    Ok(TcpStream::from(socket))
}

pub(super) fn tcp_connect_failure_reason(error: &io::Error) -> String {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => "connection refused".to_string(),
        io::ErrorKind::TimedOut => "timed out".to_string(),
        io::ErrorKind::NetworkUnreachable => "network unreachable".to_string(),
        io::ErrorKind::HostUnreachable => "host unreachable".to_string(),
        io::ErrorKind::AddrNotAvailable => "address not available".to_string(),
        io::ErrorKind::PermissionDenied => "permission denied".to_string(),
        kind => format!("{kind:?}").to_ascii_lowercase(),
    }
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        net::{Ipv4Addr, TcpListener},
    };

    use rustix::process::geteuid;

    use super::*;

    #[test]
    fn unmarked_connect_plan_reaches_loopback_target() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let mut upstream = connect_tcp(
            listener.local_addr()?,
            TransparentProxyUpstreamConnectPlan::new(Duration::from_secs(1), None),
        )?;
        let (mut accepted, _) = listener.accept()?;

        upstream.write_all(b"ping")?;
        let mut received = [0_u8; 4];
        accepted.read_exact(&mut received)?;

        assert_eq!(&received, b"ping");
        Ok(())
    }

    #[test]
    #[ignore = "requires root/CAP_NET_ADMIN to set and read SO_MARK"]
    fn marked_connect_plan_sets_socket_mark() -> Result<(), Box<dyn std::error::Error>> {
        assert!(geteuid().is_root(), "test requires root/CAP_NET_ADMIN");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let mark = NonZeroU32::new(0x5353_4102).expect("test mark should be non-zero");

        let upstream = connect_tcp(
            listener.local_addr()?,
            TransparentProxyUpstreamConnectPlan::new(
                Duration::from_secs(1),
                Some(TransparentProxyBypassMark(mark)),
            ),
        )?;
        let (_accepted, _) = listener.accept()?;
        let upstream = Socket::from(upstream);

        assert_eq!(upstream.mark()?, mark.get());
        Ok(())
    }
}
