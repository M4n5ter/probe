use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    num::NonZeroU32,
    time::{Duration, Instant},
};

use probe_core::ApplicationProtocolPolicy;
use probe_io::{TcpConnectOptions, TcpSocketMark, connect_tcp};

use crate::{
    MitmProxyError,
    authority::ObservedAuthority,
    error::io_error,
    tls::{TlsClientStream, TlsUpstreamConnector, UpstreamTlsConfig},
};

const MAX_UPSTREAM_CONNECT_CANDIDATES: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum UpstreamTlsMode {
    #[default]
    Never,
    Auto,
    Always,
}

pub(crate) struct UpstreamConnector {
    mode: UpstreamTlsMode,
    tls: Option<TlsUpstreamConnector>,
    socket_mark: Option<TcpSocketMark>,
}

impl UpstreamConnector {
    pub(crate) fn from_config(
        mode: UpstreamTlsMode,
        config: Option<&UpstreamTlsConfig>,
        socket_mark: Option<NonZeroU32>,
        application_protocols: &ApplicationProtocolPolicy,
    ) -> Result<Self, MitmProxyError> {
        let tls = match (mode, config) {
            (UpstreamTlsMode::Never, None) => None,
            (UpstreamTlsMode::Never, Some(_)) => {
                return Err(MitmProxyError::InvalidConfig(
                    "upstream TLS config requires upstream_tls_mode = auto or always".to_string(),
                ));
            }
            (UpstreamTlsMode::Auto | UpstreamTlsMode::Always, Some(config)) => Some(
                TlsUpstreamConnector::from_config(config, application_protocols)?,
            ),
            (UpstreamTlsMode::Auto | UpstreamTlsMode::Always, None) => {
                return Err(MitmProxyError::InvalidConfig(
                    "upstream TLS mode requires upstream TLS config".to_string(),
                ));
            }
        };
        Ok(Self {
            mode,
            tls,
            socket_mark: socket_mark.map(TcpSocketMark::new),
        })
    }

    pub(crate) fn connect(
        &self,
        target: SocketAddr,
        authority: ObservedAuthority<'_>,
        timeout: Duration,
        use_tls: bool,
    ) -> Result<UpstreamConnection, MitmProxyError> {
        let mut options = TcpConnectOptions::new(timeout);
        if let Some(mark) = self.socket_mark {
            options = options.with_socket_mark(mark);
        }
        let stream =
            connect_tcp(target, options).map_err(io_error("connect MITM proxy upstream"))?;
        configure_stream(&stream, timeout)?;
        if use_tls {
            let tls = self.tls.as_ref().ok_or_else(|| {
                MitmProxyError::InvalidConfig(
                    "upstream TLS was selected without a TLS connector".to_string(),
                )
            })?;
            return tls
                .connect(stream, authority.candidates())
                .map(Box::new)
                .map(UpstreamConnection::Tls);
        }
        Ok(UpstreamConnection::Plain(stream))
    }

    pub(crate) fn connect_first(
        &self,
        targets: impl IntoIterator<Item = SocketAddr>,
        authority: ObservedAuthority<'_>,
        timeout: Duration,
        use_tls: bool,
    ) -> Result<Option<UpstreamConnection>, MitmProxyError> {
        let mut last_error = None;
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        for target in targets.into_iter().take(MAX_UPSTREAM_CONNECT_CANDIDATES) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining == Duration::ZERO {
                break;
            }
            match self.connect(target, authority, remaining, use_tls) {
                Ok(connection) => return Ok(Some(connection)),
                Err(error) => last_error = Some(error),
            }
        }
        match last_error {
            Some(error) => Err(error),
            None => Ok(None),
        }
    }

    pub(crate) fn uses_tls_for_downstream(&self, downstream_uses_tls: bool) -> bool {
        match self.mode {
            UpstreamTlsMode::Never => false,
            UpstreamTlsMode::Auto => downstream_uses_tls,
            UpstreamTlsMode::Always => true,
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

    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), MitmProxyError> {
        match self {
            Self::Plain(stream) => stream.set_read_timeout(timeout),
            Self::Tls(stream) => stream.sock.set_read_timeout(timeout),
        }
        .map_err(io_error("set MITM proxy upstream read timeout"))
    }

    pub(crate) fn shutdown_write(&mut self) -> Result<(), MitmProxyError> {
        match self {
            Self::Plain(stream) => stream
                .shutdown(Shutdown::Write)
                .map_err(io_error("shutdown MITM proxy upstream write half")),
            Self::Tls(stream) => {
                stream.conn.send_close_notify();
                stream
                    .flush()
                    .map_err(io_error("send MITM proxy upstream TLS close notify"))
            }
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
