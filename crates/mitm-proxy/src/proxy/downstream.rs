use std::{
    io::{Read, Write},
    net::TcpStream,
    sync::Arc,
};

use crate::{
    MitmProxyError,
    error::io_error,
    tls::{TlsServerStream, TlsTerminationConfig, TlsTerminator},
};

pub(super) struct DownstreamAcceptor {
    tls: Option<Arc<TlsTerminator>>,
}

impl DownstreamAcceptor {
    pub(super) fn from_tls_config(
        tls: Option<&TlsTerminationConfig>,
    ) -> Result<Self, MitmProxyError> {
        Ok(Self {
            tls: tls
                .map(TlsTerminator::from_config)
                .transpose()?
                .map(Arc::new),
        })
    }

    pub(super) fn accept(&self, stream: TcpStream) -> Result<DownstreamStream, MitmProxyError> {
        match &self.tls {
            Some(tls) => tls.accept(stream).map(Box::new).map(DownstreamStream::Tls),
            None => Ok(DownstreamStream::Plain(stream)),
        }
    }
}

pub(super) enum DownstreamStream {
    Plain(TcpStream),
    Tls(Box<TlsServerStream>),
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

pub(super) trait DownstreamIo: Read + Write {
    fn finish(&mut self) -> Result<(), MitmProxyError>;
}

impl DownstreamIo for DownstreamStream {
    fn finish(&mut self) -> Result<(), MitmProxyError> {
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
