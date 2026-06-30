use std::{
    fs::File,
    io::{self, BufReader, Read, Write},
    net::TcpListener,
    path::Path,
    sync::Arc,
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rustls::{
    ServerConfig, ServerConnection, StreamOwned,
    pki_types::{CertificateDer, PrivateKeyDer},
};

use super::{backend::ProductProxyUpstream, websocket};
use crate::e2e::harness::e2e_error;

const TIMEOUT: Duration = Duration::from_secs(5);

type UpstreamThreadResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

pub(super) struct ProductProxyTlsWebSocketUpstreamServer {
    thread: Option<JoinHandle<UpstreamThreadResult>>,
}

impl ProductProxyTlsWebSocketUpstreamServer {
    pub(super) fn start(
        upstream: &ProductProxyUpstream,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = Arc::new(websocket_tls_server_config(upstream)?);
        let listener = TcpListener::bind(upstream.target)?;
        let expected_request = websocket::upgrade_request_bytes(&upstream.server_name);
        let thread = thread::spawn({
            let expected_request = expected_request.clone();
            move || serve_websocket_tls_upstream(listener, config, expected_request)
        });
        Ok(Self {
            thread: Some(thread),
        })
    }

    pub(super) fn wait(mut self) -> Result<(), Box<dyn std::error::Error>> {
        match self
            .thread
            .take()
            .ok_or_else(|| e2e_error("product proxy WebSocket upstream fixture already waited"))?
            .join()
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(e2e_error(format!(
                "product proxy WebSocket upstream fixture failed: {error}"
            ))
            .into()),
            Err(_) => Err(e2e_error("product proxy WebSocket upstream fixture panicked").into()),
        }
    }
}

impl Drop for ProductProxyTlsWebSocketUpstreamServer {
    fn drop(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn websocket_tls_server_config(
    upstream: &ProductProxyUpstream,
) -> Result<ServerConfig, Box<dyn std::error::Error>> {
    let certificate_chain = load_certificate_chain(&upstream.certificate_path)?;
    let private_key = load_private_key(&upstream.private_key_path)?;
    let crypto_provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    Ok(ServerConfig::builder_with_provider(crypto_provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?
        .with_no_client_auth()
        .with_single_cert(certificate_chain, private_key)?)
}

fn load_certificate_chain(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(path)?);
    let certificates = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    if certificates.is_empty() {
        return Err(e2e_error(format!(
            "product proxy WebSocket upstream certificate chain {} was empty",
            path.display()
        ))
        .into());
    }
    Ok(certificates)
}

fn load_private_key(path: &Path) -> Result<PrivateKeyDer<'static>, Box<dyn std::error::Error>> {
    let mut reader = BufReader::new(File::open(path)?);
    rustls_pemfile::private_key(&mut reader)?.ok_or_else(|| {
        e2e_error(format!(
            "product proxy WebSocket upstream private key {} was empty",
            path.display()
        ))
        .into()
    })
}

fn serve_websocket_tls_upstream(
    listener: TcpListener,
    config: Arc<ServerConfig>,
    expected_request: Vec<u8>,
) -> UpstreamThreadResult {
    let stream = accept_websocket_tls_upstream_connection(listener)?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let connection = ServerConnection::new(config)?;
    let mut stream = StreamOwned::new(connection, stream);
    let request = read_websocket_upgrade_request(&mut stream)?;
    assert_websocket_upstream_received_request(&request, &expected_request)?;
    stream.write_all(&websocket::upgrade_response_bytes())?;
    stream.write_all(&websocket::text_frame_bytes())?;
    stream.flush()?;
    Ok(())
}

fn accept_websocket_tls_upstream_connection(
    listener: TcpListener,
) -> io::Result<std::net::TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + TIMEOUT;
    loop {
        match listener.accept() {
            Ok((stream, _)) => return Ok(stream),
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                thread::sleep(Duration::from_millis(20));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out waiting for product proxy WebSocket upstream TLS connection",
                ));
            }
            Err(error) => return Err(error),
        }
    }
}

fn read_websocket_upgrade_request(
    stream: &mut StreamOwned<ServerConnection, std::net::TcpStream>,
) -> io::Result<Vec<u8>> {
    let mut request = Vec::new();
    let mut buf = [0_u8; 512];
    loop {
        let read = stream.read(&mut buf)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "TLS WebSocket client closed before HTTP Upgrade headers",
            ));
        }
        request.extend_from_slice(&buf[..read]);
        if request.windows(4).any(|window| window == b"\r\n\r\n") {
            return Ok(request);
        }
        if request.len() > 4096 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "TLS WebSocket Upgrade request exceeded e2e limit",
            ));
        }
    }
}

fn assert_websocket_upstream_received_request(
    request: &[u8],
    expected: &[u8],
) -> UpstreamThreadResult {
    if request == expected {
        return Ok(());
    }
    Err(e2e_error(format!(
        "expected {:?}, got {:?}",
        String::from_utf8_lossy(expected),
        String::from_utf8_lossy(request)
    ))
    .into())
}
