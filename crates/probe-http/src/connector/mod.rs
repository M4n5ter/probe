use std::{
    future::Future,
    io,
    net::{SocketAddr, TcpStream as StdTcpStream},
    num::NonZeroU32,
    path::PathBuf,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use http::Uri;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::rt::TokioIo;
use probe_io::{TcpConnectOptions, TcpSocketMark, connect_tcp};
use tokio::net::{TcpStream, UnixStream, lookup_host};
use tower_service::Service;

pub const DEFAULT_HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub type ProbeHttpsConnector = HttpsConnector<TcpHttpConnector>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HttpConnectionOptions {
    connect_timeout: Duration,
    socket_mark: Option<TcpSocketMark>,
}

impl HttpConnectionOptions {
    pub fn new(connect_timeout: Duration) -> Self {
        Self {
            connect_timeout,
            socket_mark: None,
        }
    }

    pub fn with_connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = connect_timeout;
        self
    }

    pub fn with_socket_mark(mut self, mark: NonZeroU32) -> Self {
        self.socket_mark = Some(TcpSocketMark::new(mark));
        self
    }

    fn connect_options(self) -> TcpConnectOptions {
        let mut options = TcpConnectOptions::new(self.connect_timeout);
        if let Some(mark) = self.socket_mark {
            options = options.with_socket_mark(mark);
        }
        options
    }
}

impl Default for HttpConnectionOptions {
    fn default() -> Self {
        Self::new(DEFAULT_HTTP_CONNECT_TIMEOUT)
    }
}

#[derive(Clone, Debug)]
pub struct TcpHttpConnector {
    connection: HttpConnectionOptions,
}

impl TcpHttpConnector {
    pub fn new(connection: HttpConnectionOptions) -> Self {
        Self { connection }
    }
}

impl Service<Uri> for TcpHttpConnector {
    type Response = TokioIo<TcpStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, uri: Uri) -> Self::Future {
        let connection = self.connection;
        Box::pin(async move { connect_uri(uri, connection).await.map(TokioIo::new) })
    }
}

#[derive(Clone, Debug)]
pub struct UnixHttpConnector {
    path: PathBuf,
}

impl UnixHttpConnector {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }
}

impl Service<Uri> for UnixHttpConnector {
    type Response = TokioIo<UnixStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _uri: Uri) -> Self::Future {
        let path = self.path.clone();
        Box::pin(async move { UnixStream::connect(path).await.map(TokioIo::new) })
    }
}

pub fn https_connector(
    tls: rustls::ClientConfig,
    connection: HttpConnectionOptions,
) -> ProbeHttpsConnector {
    HttpsConnectorBuilder::new()
        .with_tls_config(tls)
        .https_or_http()
        .enable_http1()
        .wrap_connector(TcpHttpConnector::new(connection))
}

async fn connect_uri(uri: Uri, connection: HttpConnectionOptions) -> io::Result<TcpStream> {
    let (host, port) = endpoint_host_port(&uri)?;
    let addresses = lookup_host((host.as_str(), port))
        .await?
        .collect::<Vec<_>>();
    let mut last_error = None;
    for address in addresses {
        match connect_address(address, connection).await {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("no socket addresses resolved for {host}:{port}"),
        )
    }))
}

fn endpoint_host_port(uri: &Uri) -> io::Result<(String, u16)> {
    let scheme = uri.scheme_str().unwrap_or("http");
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unsupported HTTP scheme {other}"),
            ));
        }
    };
    let host = uri.host().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "HTTP endpoint is missing a host",
        )
    })?;
    Ok((host.to_string(), uri.port_u16().unwrap_or(default_port)))
}

async fn connect_address(
    address: SocketAddr,
    connection: HttpConnectionOptions,
) -> io::Result<TcpStream> {
    let options = connection.connect_options();
    let stream = tokio::task::spawn_blocking(move || connect_tcp(address, options))
        .await
        .map_err(|source| io::Error::other(source.to_string()))??;
    stream_to_tokio(stream)
}

fn stream_to_tokio(stream: StdTcpStream) -> io::Result<TcpStream> {
    stream.set_nonblocking(true)?;
    TcpStream::from_std(stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_options_preserve_socket_mark() {
        let mark = NonZeroU32::new(0x5450_0102).expect("non-zero mark");

        let options = HttpConnectionOptions::new(Duration::from_secs(3)).with_socket_mark(mark);

        assert_eq!(
            options.connect_options(),
            TcpConnectOptions::new(Duration::from_secs(3))
                .with_socket_mark(TcpSocketMark::new(mark))
        );
    }

    #[test]
    fn endpoint_host_port_uses_scheme_defaults() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            endpoint_host_port(&"https://collector.example/batches".parse::<Uri>()?)?,
            ("collector.example".to_string(), 443)
        );
        assert_eq!(
            endpoint_host_port(&"http://collector.example/batches".parse::<Uri>()?)?,
            ("collector.example".to_string(), 80)
        );
        Ok(())
    }

    #[test]
    fn endpoint_host_port_preserves_explicit_port() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            endpoint_host_port(&"https://collector.example:8443/batches".parse::<Uri>()?)?,
            ("collector.example".to_string(), 8443)
        );
        Ok(())
    }

    #[test]
    fn endpoint_host_port_rejects_unsupported_scheme() {
        let uri = "ftp://collector.example/batches"
            .parse::<Uri>()
            .expect("URI");

        let error = endpoint_host_port(&uri).expect_err("unsupported scheme");

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("unsupported HTTP scheme ftp"));
    }
}
