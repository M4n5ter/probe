use std::{
    io,
    net::{SocketAddr, TcpStream},
    num::NonZeroU32,
    time::Duration,
};

use socket2::{Domain, Protocol, SockAddr, Socket, Type};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpSocketMark(NonZeroU32);

impl TcpSocketMark {
    pub fn new(mark: NonZeroU32) -> Self {
        Self(mark)
    }

    fn get(self) -> u32 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TcpConnectOptions {
    timeout: Duration,
    socket_mark: Option<TcpSocketMark>,
}

impl TcpConnectOptions {
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            socket_mark: None,
        }
    }

    pub fn with_socket_mark(mut self, socket_mark: TcpSocketMark) -> Self {
        self.socket_mark = Some(socket_mark);
        self
    }
}

pub fn connect_tcp(target: SocketAddr, options: TcpConnectOptions) -> io::Result<TcpStream> {
    let socket = Socket::new(
        Domain::for_address(target),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    if let Some(mark) = options.socket_mark {
        socket.set_mark(mark.get())?;
    }
    socket.connect_timeout(&SockAddr::from(target), options.timeout)?;
    Ok(TcpStream::from(socket))
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
    fn unmarked_connect_reaches_loopback_target() -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let mut upstream = connect_tcp(
            listener.local_addr()?,
            TcpConnectOptions::new(Duration::from_secs(1)),
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
    fn marked_connect_sets_socket_mark() -> Result<(), Box<dyn std::error::Error>> {
        assert!(geteuid().is_root(), "test requires root/CAP_NET_ADMIN");
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let mark = TcpSocketMark::new(NonZeroU32::new(0x5450_0102).expect("non-zero mark"));

        let upstream = connect_tcp(
            listener.local_addr()?,
            TcpConnectOptions::new(Duration::from_secs(1)).with_socket_mark(mark),
        )?;
        let (_accepted, _) = listener.accept()?;
        let upstream = Socket::from(upstream);

        assert_eq!(upstream.mark()?, mark.get());
        Ok(())
    }
}
