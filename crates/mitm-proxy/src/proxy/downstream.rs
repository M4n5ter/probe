use std::{
    io::{Read, Write},
    net::{Shutdown, TcpStream},
    sync::Arc,
    time::Duration,
};

use crate::{
    MitmProxyError,
    error::io_error,
    tls::{TlsServerStream, TlsTerminationConfig, TlsTerminator},
};
use probe_core::ApplicationProtocolPolicy;

const TLS_HANDSHAKE_RECORD_TYPE: u8 = 0x16;
const TLS_RECORD_VERSION_MAJOR: u8 = 0x03;

pub(super) struct DownstreamAcceptor {
    tls: Option<Arc<TlsTerminator>>,
}

impl DownstreamAcceptor {
    pub(super) fn from_tls_config(
        tls: Option<&TlsTerminationConfig>,
        application_protocols: &ApplicationProtocolPolicy,
    ) -> Result<Self, MitmProxyError> {
        Ok(Self {
            tls: tls
                .map(|tls| TlsTerminator::from_config(tls, application_protocols))
                .transpose()?
                .map(Arc::new),
        })
    }

    pub(super) fn accept(&self, stream: TcpStream) -> Result<DownstreamStream, MitmProxyError> {
        let Some(tls) = &self.tls else {
            return Ok(DownstreamStream::Plain(stream));
        };
        if stream_starts_with_tls_handshake(&stream)? {
            return tls.accept(stream).map(Box::new).map(DownstreamStream::Tls);
        }
        Ok(DownstreamStream::Plain(stream))
    }
}

fn stream_starts_with_tls_handshake(stream: &TcpStream) -> Result<bool, MitmProxyError> {
    let mut prefix = [0_u8; 2];
    let read = stream
        .peek(&mut prefix)
        .map_err(io_error("peek MITM proxy downstream protocol"))?;
    Ok(matches!(
        prefix[..read],
        [TLS_HANDSHAKE_RECORD_TYPE] | [TLS_HANDSHAKE_RECORD_TYPE, TLS_RECORD_VERSION_MAJOR]
    ))
}

pub(super) enum DownstreamStream {
    Plain(TcpStream),
    Tls(Box<TlsServerStream>),
}

impl DownstreamStream {
    pub(super) fn uses_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    pub(super) fn tls_server_name(&self) -> Option<&str> {
        match self {
            Self::Plain(_) => None,
            Self::Tls(stream) => stream.conn.server_name(),
        }
    }

    pub(super) fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), MitmProxyError> {
        match self {
            Self::Plain(stream) => stream.set_read_timeout(timeout),
            Self::Tls(stream) => stream.sock.set_read_timeout(timeout),
        }
        .map_err(io_error("set MITM proxy downstream read timeout"))
    }

    pub(super) fn shutdown_write(&mut self) -> Result<(), MitmProxyError> {
        match self {
            Self::Plain(stream) => stream
                .shutdown(Shutdown::Write)
                .map_err(io_error("shutdown MITM proxy downstream write half")),
            Self::Tls(stream) => {
                stream.conn.send_close_notify();
                stream
                    .flush()
                    .map_err(io_error("send MITM proxy downstream TLS close notify"))
            }
        }
    }

    pub(super) fn finish(&mut self) -> Result<(), MitmProxyError> {
        match self {
            Self::Plain(stream) => stream
                .flush()
                .map_err(io_error("flush MITM proxy plaintext downstream")),
            Self::Tls(stream) => {
                stream.conn.send_close_notify();
                stream
                    .flush()
                    .map_err(io_error("send MITM proxy TLS close notify"))
            }
        }
    }
}

impl Read for DownstreamStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Plain(stream) => stream.read(buffer),
            Self::Tls(stream) => stream.read(buffer),
        }
    }
}

impl Write for DownstreamStream {
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
