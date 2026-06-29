use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    num::NonZeroU32,
    time::Duration,
};

use probe_io::{TcpConnectOptions, TcpSocketMark, connect_tcp};

use crate::{
    MitmProxyError,
    error::io_error,
    http::HttpMessage,
    tls::{TlsClientStream, TlsUpstreamConnector, UpstreamTlsConfig},
};

pub(crate) struct UpstreamConnector {
    tls: Option<TlsUpstreamConnector>,
    socket_mark: Option<TcpSocketMark>,
}

impl UpstreamConnector {
    pub(crate) fn from_config(
        config: Option<&UpstreamTlsConfig>,
        socket_mark: Option<NonZeroU32>,
    ) -> Result<Self, MitmProxyError> {
        let tls = config.map(TlsUpstreamConnector::from_config).transpose()?;
        Ok(Self {
            tls,
            socket_mark: socket_mark.map(TcpSocketMark::new),
        })
    }

    pub(crate) fn connect(
        &self,
        target: SocketAddr,
        request: &HttpMessage,
        timeout: Duration,
    ) -> Result<UpstreamConnection, MitmProxyError> {
        let tls_authority = self
            .tls
            .as_ref()
            .map(|_| request.authority())
            .transpose()?
            .flatten();
        let mut options = TcpConnectOptions::new(timeout);
        if let Some(mark) = self.socket_mark {
            options = options.with_socket_mark(mark);
        }
        let stream =
            connect_tcp(target, options).map_err(io_error("connect MITM proxy upstream"))?;
        configure_stream(&stream, timeout)?;
        match &self.tls {
            Some(tls) => tls
                .connect(stream, tls_authority)
                .map(Box::new)
                .map(UpstreamConnection::Tls),
            None => Ok(UpstreamConnection::Plain(stream)),
        }
    }
}

pub(crate) enum UpstreamConnection {
    Plain(TcpStream),
    Tls(Box<TlsClientStream>),
}

impl UpstreamConnection {
    pub(crate) fn finish_request(&mut self) -> Result<(), MitmProxyError> {
        match self {
            Self::Plain(stream) => stream
                .shutdown(Shutdown::Write)
                .map_err(io_error("shutdown MITM proxy upstream request")),
            Self::Tls(stream) => stream
                .flush()
                .map_err(io_error("flush MITM proxy upstream TLS request")),
        }
    }
}

impl Read for UpstreamConnection {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for UpstreamConnection {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.write(buffer),
            Self::Tls(stream) => stream.write(buffer),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Plain(stream) => stream.flush(),
            Self::Tls(stream) => stream.flush(),
        }
    }
}

fn configure_stream(stream: &TcpStream, timeout: Duration) -> Result<(), MitmProxyError> {
    stream
        .set_read_timeout(Some(timeout))
        .map_err(io_error("set MITM proxy upstream read timeout"))?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(io_error("set MITM proxy upstream write timeout"))
}
