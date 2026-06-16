use std::{
    error::Error,
    fmt,
    io::{self, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::fd::AsFd,
    thread,
    time::Duration,
};

use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    error::ErrorStack,
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    rsa::Rsa,
    ssl::{
        Error as SslError, Ssl, SslContext, SslContextBuilder, SslMethod, SslStream, SslVerifyMode,
    },
    x509::{X509, X509NameBuilder},
};

use super::{
    http::{self, ExchangeReport, HttpMessageError, HttpTrafficConfig},
    loopback::{
        LoopbackError, LoopbackRunOptions, accept_with_timeout, bind_loopback_listener,
        configure_stream, coordinate_start, delay_after_exchange,
    },
};

const SCENARIO: &str = "tls-http1-loopback";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct TlsHttp1LoopbackConfig {
    pub traffic: HttpTrafficConfig,
    pub run: LoopbackRunOptions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TlsHttp1LoopbackReport {
    pub pid: u32,
    pub listen_addr: SocketAddr,
    pub requests: usize,
    pub write_chunks: usize,
    pub client_bytes_written: usize,
    pub client_bytes_read: usize,
    pub server_bytes_read: usize,
    pub server_bytes_written: usize,
}

impl fmt::Display for TlsHttp1LoopbackReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "scenario={SCENARIO}")?;
        writeln!(formatter, "pid={}", self.pid)?;
        writeln!(formatter, "listen_addr={}", self.listen_addr)?;
        writeln!(formatter, "requests={}", self.requests)?;
        writeln!(formatter, "write_chunks={}", self.write_chunks)?;
        writeln!(
            formatter,
            "client_bytes_written={}",
            self.client_bytes_written
        )?;
        writeln!(formatter, "client_bytes_read={}", self.client_bytes_read)?;
        writeln!(formatter, "server_bytes_read={}", self.server_bytes_read)?;
        writeln!(
            formatter,
            "server_bytes_written={}",
            self.server_bytes_written
        )?;
        writeln!(formatter, "result=ok")
    }
}

#[derive(Debug)]
pub(crate) enum TlsHttp1LoopbackError {
    Loopback(LoopbackError),
    Http(HttpMessageError),
    Io {
        action: &'static str,
        source: io::Error,
    },
    OpenSslStack {
        action: &'static str,
        source: ErrorStack,
    },
    OpenSsl {
        action: &'static str,
        source: SslError,
    },
    ServerThreadPanicked,
}

impl fmt::Display for TlsHttp1LoopbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loopback(error) => write!(formatter, "{error}"),
            Self::Http(error) => write!(formatter, "{error}"),
            Self::Io { action, source } => write!(formatter, "failed to {action}: {source}"),
            Self::OpenSslStack { action, source } => {
                write!(formatter, "OpenSSL failed to {action}: {source}")
            }
            Self::OpenSsl { action, source } => {
                write!(formatter, "OpenSSL failed to {action}: {source}")
            }
            Self::ServerThreadPanicked => {
                write!(formatter, "tls-http1-loopback server thread panicked")
            }
        }
    }
}

impl Error for TlsHttp1LoopbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Loopback(error) => Some(error),
            Self::Http(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::OpenSslStack { source, .. } => Some(source),
            Self::OpenSsl { source, .. } => Some(source),
            Self::ServerThreadPanicked => None,
        }
    }
}

impl From<LoopbackError> for TlsHttp1LoopbackError {
    fn from(error: LoopbackError) -> Self {
        Self::Loopback(error)
    }
}

impl From<HttpMessageError> for TlsHttp1LoopbackError {
    fn from(error: HttpMessageError) -> Self {
        Self::Http(error)
    }
}

pub(crate) fn run_tls_http1_loopback(
    config: TlsHttp1LoopbackConfig,
) -> Result<TlsHttp1LoopbackReport, TlsHttp1LoopbackError> {
    http::validate_traffic_config(&config.traffic)?;
    let listener = bind_loopback_listener(config.run.listen_port)?;
    let listen_addr = listener
        .local_addr()
        .map_err(|source| io_error("read listener address", source))?;
    coordinate_start(&config.run.coordination, listen_addr)?;
    let (server_context, client_context) = tls_contexts()?;
    let traffic = config.traffic;
    let post_exchange_delay_ms = config.run.post_exchange_delay_ms;
    let server = thread::spawn(move || {
        serve_tls_http1(listener, traffic, server_context, post_exchange_delay_ms)
    });

    let mut client_bytes_written = 0usize;
    let mut client_bytes_read = 0usize;
    for request_index in 0..traffic.requests {
        let exchange = run_client_exchange(
            listen_addr,
            request_index,
            &traffic,
            config.run.connect_write_delay_ms,
            config.run.post_exchange_delay_ms,
            &client_context,
        )?;
        client_bytes_written = client_bytes_written.saturating_add(exchange.bytes_written);
        client_bytes_read = client_bytes_read.saturating_add(exchange.bytes_read);
    }

    let server_report = server
        .join()
        .map_err(|_| TlsHttp1LoopbackError::ServerThreadPanicked)??;
    Ok(TlsHttp1LoopbackReport {
        pid: std::process::id(),
        listen_addr,
        requests: traffic.requests,
        write_chunks: traffic.write_chunks,
        client_bytes_written,
        client_bytes_read,
        server_bytes_read: server_report.bytes_read,
        server_bytes_written: server_report.bytes_written,
    })
}

fn run_client_exchange(
    listen_addr: SocketAddr,
    request_index: usize,
    config: &HttpTrafficConfig,
    connect_write_delay_ms: u64,
    post_exchange_delay_ms: u64,
    context: &SslContext,
) -> Result<ExchangeReport, TlsHttp1LoopbackError> {
    let stream = TcpStream::connect(listen_addr)
        .map_err(|source| io_error("connect to TLS loopback fixture server", source))?;
    configure_stream(&stream)?;
    if connect_write_delay_ms > 0 {
        thread::sleep(Duration::from_millis(connect_write_delay_ms));
    }
    let mut stream = tls_stream(stream, context, TlsRole::Client)?;
    let request = http::request(request_index, config.request_body_bytes);
    write_tls_in_chunks(&mut stream, &request, config.write_chunks)?;
    let response = http::read_message(&mut stream, config.response_body_bytes)?;
    http::validate_response(&response, request_index, config.response_body_bytes)?;
    delay_after_exchange(post_exchange_delay_ms);
    let _ = stream.shutdown();
    Ok(ExchangeReport {
        bytes_written: request.len(),
        bytes_read: response.len(),
    })
}

fn serve_tls_http1(
    listener: TcpListener,
    config: HttpTrafficConfig,
    context: SslContext,
    post_exchange_delay_ms: u64,
) -> Result<ExchangeReport, TlsHttp1LoopbackError> {
    let mut bytes_read = 0usize;
    let mut bytes_written = 0usize;
    for request_index in 0..config.requests {
        let (stream, _) = accept_with_timeout(&listener)?;
        configure_stream(&stream)?;
        let mut stream = tls_stream(stream, &context, TlsRole::Server)?;
        let request = http::read_message(&mut stream, config.request_body_bytes)?;
        http::validate_request(&request, request_index, config.request_body_bytes)?;
        let response = http::response(request_index, config.response_body_bytes);
        stream
            .write_all(&response)
            .map_err(|source| io_error("write TLS fixture response", source))?;
        delay_after_exchange(post_exchange_delay_ms);
        let _ = stream.shutdown();
        bytes_read = bytes_read.saturating_add(request.len());
        bytes_written = bytes_written.saturating_add(response.len());
    }
    Ok(ExchangeReport {
        bytes_read,
        bytes_written,
    })
}

fn write_tls_in_chunks(
    stream: &mut SslStream<TcpStream>,
    bytes: &[u8],
    chunks: usize,
) -> Result<(), TlsHttp1LoopbackError> {
    let chunk_size = http::chunk_size(bytes.len(), chunks);
    for chunk in bytes.chunks(chunk_size) {
        stream
            .write_all(chunk)
            .map_err(|source| io_error("write TLS fixture request chunk", source))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsRole {
    Client,
    Server,
}

fn tls_stream(
    stream: TcpStream,
    context: &SslContext,
    role: TlsRole,
) -> Result<SslStream<TcpStream>, TlsHttp1LoopbackError> {
    let mut ssl =
        Ssl::new(context).map_err(|source| openssl_stack_error("create SSL object", source))?;
    match role {
        TlsRole::Client => ssl.set_connect_state(),
        TlsRole::Server => ssl.set_accept_state(),
    }
    associate_ssl_fd_for_probe(&mut ssl, &stream)?;
    let mut stream = SslStream::new(ssl, stream)
        .map_err(|source| openssl_stack_error("create SSL stream", source))?;
    match role {
        TlsRole::Client => stream
            .connect()
            .map_err(|source| openssl_error("perform client TLS handshake", source))?,
        TlsRole::Server => stream
            .accept()
            .map_err(|source| openssl_error("perform server TLS handshake", source))?,
    }
    Ok(stream)
}

fn associate_ssl_fd_for_probe(
    ssl: &mut Ssl,
    stream: &TcpStream,
) -> Result<(), TlsHttp1LoopbackError> {
    e2e_libssl_ffi::associate_ssl_fd(ssl, stream.as_fd())
        .map_err(|source| openssl_stack_error("associate SSL object with socket fd", source))
}

fn tls_contexts() -> Result<(SslContext, SslContext), TlsHttp1LoopbackError> {
    let (private_key, certificate) = self_signed_certificate()?;
    let mut server = SslContextBuilder::new(SslMethod::tls_server())
        .map_err(|source| openssl_stack_error("create server TLS context", source))?;
    server
        .set_private_key(&private_key)
        .map_err(|source| openssl_stack_error("install server private key", source))?;
    server
        .set_certificate(&certificate)
        .map_err(|source| openssl_stack_error("install server certificate", source))?;
    server
        .check_private_key()
        .map_err(|source| openssl_stack_error("check server private key", source))?;

    let mut client = SslContextBuilder::new(SslMethod::tls_client())
        .map_err(|source| openssl_stack_error("create client TLS context", source))?;
    client.set_verify(SslVerifyMode::NONE);

    Ok((server.build(), client.build()))
}

fn self_signed_certificate() -> Result<(PKey<Private>, X509), TlsHttp1LoopbackError> {
    let rsa =
        Rsa::generate(2048).map_err(|source| openssl_stack_error("generate RSA key", source))?;
    let private_key =
        PKey::from_rsa(rsa).map_err(|source| openssl_stack_error("create private key", source))?;
    let mut name =
        X509NameBuilder::new().map_err(|source| openssl_stack_error("create X509 name", source))?;
    name.append_entry_by_nid(Nid::COMMONNAME, "localhost")
        .map_err(|source| openssl_stack_error("set certificate common name", source))?;
    let name = name.build();

    let mut certificate =
        X509::builder().map_err(|source| openssl_stack_error("create certificate", source))?;
    certificate
        .set_version(2)
        .map_err(|source| openssl_stack_error("set certificate version", source))?;
    let serial = BigNum::from_u32(1)
        .and_then(|serial| serial.to_asn1_integer())
        .map_err(|source| openssl_stack_error("create certificate serial", source))?;
    certificate
        .set_serial_number(&serial)
        .map_err(|source| openssl_stack_error("set certificate serial", source))?;
    certificate
        .set_subject_name(&name)
        .map_err(|source| openssl_stack_error("set certificate subject", source))?;
    certificate
        .set_issuer_name(&name)
        .map_err(|source| openssl_stack_error("set certificate issuer", source))?;
    certificate
        .set_pubkey(&private_key)
        .map_err(|source| openssl_stack_error("set certificate public key", source))?;
    let not_before = Asn1Time::days_from_now(0)
        .map_err(|source| openssl_stack_error("create certificate not_before", source))?;
    certificate
        .set_not_before(&not_before)
        .map_err(|source| openssl_stack_error("set certificate not_before", source))?;
    let not_after = Asn1Time::days_from_now(1)
        .map_err(|source| openssl_stack_error("create certificate not_after", source))?;
    certificate
        .set_not_after(&not_after)
        .map_err(|source| openssl_stack_error("set certificate not_after", source))?;
    certificate
        .sign(&private_key, MessageDigest::sha256())
        .map_err(|source| openssl_stack_error("sign certificate", source))?;

    Ok((private_key, certificate.build()))
}

fn io_error(action: &'static str, source: io::Error) -> TlsHttp1LoopbackError {
    TlsHttp1LoopbackError::Io { action, source }
}

fn openssl_stack_error(action: &'static str, source: ErrorStack) -> TlsHttp1LoopbackError {
    TlsHttp1LoopbackError::OpenSslStack { action, source }
}

fn openssl_error(action: &'static str, source: SslError) -> TlsHttp1LoopbackError {
    TlsHttp1LoopbackError::OpenSsl { action, source }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_http1_loopback_fixture_runs() -> Result<(), Box<dyn Error>> {
        let report = run_tls_http1_loopback(TlsHttp1LoopbackConfig {
            traffic: HttpTrafficConfig {
                requests: 1,
                request_body_bytes: 48,
                response_body_bytes: 24,
                write_chunks: 2,
            },
            run: LoopbackRunOptions::default(),
        })?;

        assert_eq!(report.requests, 1);
        assert_eq!(report.write_chunks, 2);
        assert_eq!(report.client_bytes_written, report.server_bytes_read);
        assert_eq!(report.client_bytes_read, report.server_bytes_written);
        Ok(())
    }
}
