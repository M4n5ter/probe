use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
    net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

const SCENARIO: &str = "http1-loopback";
const IO_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_REQUESTS: usize = 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_WRITE_CHUNKS: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Http1LoopbackConfig {
    pub requests: usize,
    pub request_body_bytes: usize,
    pub response_body_bytes: usize,
    pub write_chunks: usize,
}

impl Default for Http1LoopbackConfig {
    fn default() -> Self {
        Self {
            requests: 1,
            request_body_bytes: 64,
            response_body_bytes: 32,
            write_chunks: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Http1LoopbackReport {
    pub pid: u32,
    pub listen_addr: SocketAddr,
    pub requests: usize,
    pub write_chunks: usize,
    pub client_bytes_written: usize,
    pub client_bytes_read: usize,
    pub server_bytes_read: usize,
    pub server_bytes_written: usize,
}

impl fmt::Display for Http1LoopbackReport {
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
pub(crate) enum Http1LoopbackError {
    InvalidConfig(String),
    Io {
        action: &'static str,
        source: io::Error,
    },
    InvalidHttp(String),
    ServerThreadPanicked,
}

impl fmt::Display for Http1LoopbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => {
                write!(formatter, "invalid http1-loopback config: {reason}")
            }
            Self::Io { action, source } => write!(formatter, "failed to {action}: {source}"),
            Self::InvalidHttp(reason) => {
                write!(formatter, "invalid fixture HTTP exchange: {reason}")
            }
            Self::ServerThreadPanicked => {
                write!(formatter, "http1-loopback server thread panicked")
            }
        }
    }
}

impl Error for Http1LoopbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidConfig(_) | Self::InvalidHttp(_) | Self::ServerThreadPanicked => None,
        }
    }
}

pub(crate) fn run_http1_loopback(
    config: Http1LoopbackConfig,
) -> Result<Http1LoopbackReport, Http1LoopbackError> {
    validate_config(config)?;
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .map_err(|source| io_error("bind loopback TCP listener", source))?;
    listener
        .set_nonblocking(true)
        .map_err(|source| io_error("set listener nonblocking", source))?;
    let listen_addr = listener
        .local_addr()
        .map_err(|source| io_error("read listener address", source))?;
    let server_config = config;
    let server = thread::spawn(move || serve_http1(listener, server_config));

    let mut client_bytes_written = 0usize;
    let mut client_bytes_read = 0usize;
    for request_index in 0..config.requests {
        let exchange = run_client_exchange(listen_addr, request_index, config)?;
        client_bytes_written = client_bytes_written.saturating_add(exchange.bytes_written);
        client_bytes_read = client_bytes_read.saturating_add(exchange.bytes_read);
    }

    let server_report = server
        .join()
        .map_err(|_| Http1LoopbackError::ServerThreadPanicked)??;
    Ok(Http1LoopbackReport {
        pid: std::process::id(),
        listen_addr,
        requests: config.requests,
        write_chunks: config.write_chunks,
        client_bytes_written,
        client_bytes_read,
        server_bytes_read: server_report.bytes_read,
        server_bytes_written: server_report.bytes_written,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ExchangeReport {
    bytes_written: usize,
    bytes_read: usize,
}

fn run_client_exchange(
    listen_addr: SocketAddr,
    request_index: usize,
    config: Http1LoopbackConfig,
) -> Result<ExchangeReport, Http1LoopbackError> {
    let mut stream = TcpStream::connect(listen_addr)
        .map_err(|source| io_error("connect to loopback fixture server", source))?;
    configure_stream(&stream)?;
    let request = http_request(request_index, config.request_body_bytes);
    write_in_chunks(&mut stream, &request, config.write_chunks)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|source| io_error("half-close client write side", source))?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|source| io_error("read HTTP fixture response", source))?;
    validate_response(&response, request_index, config.response_body_bytes)?;
    Ok(ExchangeReport {
        bytes_written: request.len(),
        bytes_read: response.len(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ServerReport {
    bytes_read: usize,
    bytes_written: usize,
}

fn serve_http1(
    listener: TcpListener,
    config: Http1LoopbackConfig,
) -> Result<ServerReport, Http1LoopbackError> {
    let mut bytes_read = 0usize;
    let mut bytes_written = 0usize;
    for request_index in 0..config.requests {
        let (mut stream, _) = accept_with_timeout(&listener)?;
        configure_stream(&stream)?;
        let mut request = Vec::new();
        stream
            .read_to_end(&mut request)
            .map_err(|source| io_error("read HTTP fixture request", source))?;
        validate_request(&request, request_index, config.request_body_bytes)?;
        let response = http_response(request_index, config.response_body_bytes);
        stream
            .write_all(&response)
            .map_err(|source| io_error("write HTTP fixture response", source))?;
        bytes_read = bytes_read.saturating_add(request.len());
        bytes_written = bytes_written.saturating_add(response.len());
    }
    Ok(ServerReport {
        bytes_read,
        bytes_written,
    })
}

fn accept_with_timeout(
    listener: &TcpListener,
) -> Result<(TcpStream, SocketAddr), Http1LoopbackError> {
    let deadline = Instant::now() + IO_TIMEOUT;
    loop {
        match listener.accept() {
            Ok(accepted) => return Ok(accepted),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(Http1LoopbackError::InvalidHttp(
                        "timed out waiting for fixture client connection".to_string(),
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(source) => return Err(io_error("accept fixture client connection", source)),
        }
    }
}

fn configure_stream(stream: &TcpStream) -> Result<(), Http1LoopbackError> {
    stream
        .set_nodelay(true)
        .map_err(|source| io_error("set TCP_NODELAY", source))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .map_err(|source| io_error("set read timeout", source))?;
    stream
        .set_write_timeout(Some(IO_TIMEOUT))
        .map_err(|source| io_error("set write timeout", source))
}

fn write_in_chunks(
    stream: &mut TcpStream,
    bytes: &[u8],
    chunks: usize,
) -> Result<(), Http1LoopbackError> {
    let chunk_size = bytes.len().div_ceil(chunks).max(1);
    for chunk in bytes.chunks(chunk_size) {
        let written = write_chunk_with_write_syscall(stream, chunk)
            .map_err(|source| io_error("write HTTP fixture request chunk", source))?;
        if written != chunk.len() {
            return Err(Http1LoopbackError::InvalidHttp(format!(
                "partial fixture request chunk write: wrote {written} of {} bytes",
                chunk.len()
            )));
        }
    }
    Ok(())
}

fn write_chunk_with_write_syscall(stream: &TcpStream, chunk: &[u8]) -> io::Result<usize> {
    rustix::io::write(stream, chunk).map_err(Into::into)
}

fn http_request(request_index: usize, body_bytes: usize) -> Vec<u8> {
    let body = deterministic_body("request", request_index, body_bytes);
    let header = format!(
        "POST /sssa-e2e/{request_index} HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         User-Agent: sssa-e2e-fixture\r\n\
         Connection: close\r\n\
         X-SSSA-E2E-Request: {request_index}\r\n\
         Content-Length: {}\r\n\
         \r\n",
        body.len()
    );
    [header.as_bytes(), &body].concat()
}

fn http_response(request_index: usize, body_bytes: usize) -> Vec<u8> {
    let body = deterministic_body("response", request_index, body_bytes);
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Connection: close\r\n\
         X-SSSA-E2E-Response: {request_index}\r\n\
         Content-Length: {}\r\n\
         \r\n",
        body.len()
    );
    [header.as_bytes(), &body].concat()
}

fn deterministic_body(label: &str, request_index: usize, len: usize) -> Vec<u8> {
    let pattern = format!("sssa-e2e-{label}-{request_index}-");
    let pattern = pattern.as_bytes();
    let mut body = Vec::with_capacity(len);
    while body.len() < len {
        let remaining = len - body.len();
        let take = remaining.min(pattern.len());
        body.extend_from_slice(&pattern[..take]);
    }
    body
}

fn validate_request(
    bytes: &[u8],
    request_index: usize,
    expected_body_bytes: usize,
) -> Result<(), Http1LoopbackError> {
    validate_http_message(
        bytes,
        &format!("POST /sssa-e2e/{request_index} HTTP/1.1"),
        &format!("X-SSSA-E2E-Request: {request_index}"),
        expected_body_bytes,
    )
}

fn validate_response(
    bytes: &[u8],
    request_index: usize,
    expected_body_bytes: usize,
) -> Result<(), Http1LoopbackError> {
    validate_http_message(
        bytes,
        "HTTP/1.1 200 OK",
        &format!("X-SSSA-E2E-Response: {request_index}"),
        expected_body_bytes,
    )
}

fn validate_http_message(
    bytes: &[u8],
    start_line: &str,
    marker_header: &str,
    expected_body_bytes: usize,
) -> Result<(), Http1LoopbackError> {
    let message = std::str::from_utf8(bytes)
        .map_err(|error| Http1LoopbackError::InvalidHttp(error.to_string()))?;
    if !message.starts_with(start_line) {
        return Err(Http1LoopbackError::InvalidHttp(format!(
            "message did not start with {start_line}"
        )));
    }
    if !message.contains(marker_header) {
        return Err(Http1LoopbackError::InvalidHttp(format!(
            "message did not contain {marker_header}"
        )));
    }
    let Some((headers, body)) = message.split_once("\r\n\r\n") else {
        return Err(Http1LoopbackError::InvalidHttp(
            "message did not contain HTTP header terminator".to_string(),
        ));
    };
    let expected_content_length = format!("Content-Length: {expected_body_bytes}");
    if !headers.contains(&expected_content_length) {
        return Err(Http1LoopbackError::InvalidHttp(format!(
            "message did not contain {expected_content_length}"
        )));
    }
    if body.len() != expected_body_bytes {
        return Err(Http1LoopbackError::InvalidHttp(format!(
            "body length {} expected {expected_body_bytes}",
            body.len()
        )));
    }
    Ok(())
}

fn validate_config(config: Http1LoopbackConfig) -> Result<(), Http1LoopbackError> {
    if config.requests == 0 || config.requests > MAX_REQUESTS {
        return Err(Http1LoopbackError::InvalidConfig(format!(
            "requests must be in 1..={MAX_REQUESTS}"
        )));
    }
    if config.request_body_bytes > MAX_BODY_BYTES {
        return Err(Http1LoopbackError::InvalidConfig(format!(
            "request-body-bytes must be <= {MAX_BODY_BYTES}"
        )));
    }
    if config.response_body_bytes > MAX_BODY_BYTES {
        return Err(Http1LoopbackError::InvalidConfig(format!(
            "response-body-bytes must be <= {MAX_BODY_BYTES}"
        )));
    }
    if config.write_chunks == 0 || config.write_chunks > MAX_WRITE_CHUNKS {
        return Err(Http1LoopbackError::InvalidConfig(format!(
            "write-chunks must be in 1..={MAX_WRITE_CHUNKS}"
        )));
    }
    Ok(())
}

fn io_error(action: &'static str, source: io::Error) -> Http1LoopbackError {
    Http1LoopbackError::Io { action, source }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http1_loopback_fixture_runs_multiple_chunked_requests() -> Result<(), Box<dyn Error>> {
        let report = run_http1_loopback(Http1LoopbackConfig {
            requests: 2,
            request_body_bytes: 96,
            response_body_bytes: 48,
            write_chunks: 3,
        })?;

        assert_eq!(report.requests, 2);
        assert_eq!(report.write_chunks, 3);
        assert_eq!(report.client_bytes_written, report.server_bytes_read);
        assert_eq!(report.client_bytes_read, report.server_bytes_written);
        assert!(report.client_bytes_written > 0);
        assert!(report.client_bytes_read > 0);
        Ok(())
    }
}
