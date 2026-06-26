use std::{
    error::Error,
    fmt,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    thread,
};

use super::loopback::{
    LoopbackError, LoopbackRunOptions, accept_with_timeout, bind_loopback_listener,
    configure_stream, coordinate_start, delay_after_exchange,
};

const SCENARIO: &str = "websocket-loopback";
const REQUEST_TARGET: &str = "/chat";
const SUBPROTOCOL: &str = "chat";
const RFC_SAMPLE_WEBSOCKET_KEY: &str = "dGhlIHNhbXBsZSBub25jZQ==";
const RFC_SAMPLE_WEBSOCKET_ACCEPT: &str = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
const MAX_CONNECTIONS: usize = 1024;
const MAX_FRAME_PAYLOAD_BYTES: usize = 125;
const MAX_WRITE_CHUNKS: usize = 1024;
const HEADER_READ_LIMIT: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebSocketLoopbackConfig {
    pub traffic: WebSocketTrafficConfig,
    pub run: LoopbackRunOptions,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WebSocketTrafficConfig {
    pub connections: usize,
    pub frame_payload_bytes: usize,
    pub write_chunks: usize,
}

impl Default for WebSocketTrafficConfig {
    fn default() -> Self {
        Self {
            connections: 1,
            frame_payload_bytes: 2,
            write_chunks: 1,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WebSocketLoopbackReport {
    pub pid: u32,
    pub listen_addr: SocketAddr,
    pub connections: usize,
    pub write_chunks: usize,
    pub frame_payload_bytes: usize,
    pub client_bytes_written: usize,
    pub client_bytes_read: usize,
    pub server_bytes_read: usize,
    pub server_bytes_written: usize,
}

impl fmt::Display for WebSocketLoopbackReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "scenario={SCENARIO}")?;
        writeln!(formatter, "pid={}", self.pid)?;
        writeln!(formatter, "listen_addr={}", self.listen_addr)?;
        writeln!(formatter, "connections={}", self.connections)?;
        writeln!(formatter, "write_chunks={}", self.write_chunks)?;
        writeln!(
            formatter,
            "frame_payload_bytes={}",
            self.frame_payload_bytes
        )?;
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
pub(crate) enum WebSocketLoopbackError {
    Loopback(LoopbackError),
    InvalidConfig(String),
    InvalidMessage(String),
    Io {
        action: &'static str,
        source: io::Error,
    },
    ServerThreadPanicked,
}

impl fmt::Display for WebSocketLoopbackError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Loopback(error) => write!(formatter, "{error}"),
            Self::InvalidConfig(reason) => write!(formatter, "invalid WebSocket config: {reason}"),
            Self::InvalidMessage(reason) => {
                write!(formatter, "invalid WebSocket message: {reason}")
            }
            Self::Io { action, source } => write!(formatter, "failed to {action}: {source}"),
            Self::ServerThreadPanicked => {
                write!(formatter, "websocket-loopback server thread panicked")
            }
        }
    }
}

impl Error for WebSocketLoopbackError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Loopback(error) => Some(error),
            Self::Io { source, .. } => Some(source),
            Self::InvalidConfig(_) | Self::InvalidMessage(_) | Self::ServerThreadPanicked => None,
        }
    }
}

impl From<LoopbackError> for WebSocketLoopbackError {
    fn from(error: LoopbackError) -> Self {
        Self::Loopback(error)
    }
}

pub(crate) fn run_websocket_loopback(
    config: WebSocketLoopbackConfig,
) -> Result<WebSocketLoopbackReport, WebSocketLoopbackError> {
    validate_traffic_config(&config.traffic)?;
    let listener = bind_loopback_listener(config.run.listen_port)?;
    let listen_addr = listener
        .local_addr()
        .map_err(|source| io_error("read listener address", source))?;
    coordinate_start(&config.run.coordination, listen_addr)?;
    let traffic = config.traffic;
    let post_exchange_delay_ms = config.run.post_exchange_delay_ms;
    let server = thread::spawn(move || serve_websocket(listener, traffic, post_exchange_delay_ms));

    let mut client_bytes_written = 0usize;
    let mut client_bytes_read = 0usize;
    for connection_index in 0..traffic.connections {
        let exchange = run_client_exchange(
            listen_addr,
            connection_index,
            &traffic,
            config.run.connect_write_delay_ms,
            config.run.post_exchange_delay_ms,
        )?;
        client_bytes_written = client_bytes_written.saturating_add(exchange.bytes_written);
        client_bytes_read = client_bytes_read.saturating_add(exchange.bytes_read);
    }

    let server_report = server
        .join()
        .map_err(|_| WebSocketLoopbackError::ServerThreadPanicked)??;
    Ok(WebSocketLoopbackReport {
        pid: std::process::id(),
        listen_addr,
        connections: traffic.connections,
        write_chunks: traffic.write_chunks,
        frame_payload_bytes: traffic.frame_payload_bytes,
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
    connection_index: usize,
    traffic: &WebSocketTrafficConfig,
    connect_write_delay_ms: u64,
    post_exchange_delay_ms: u64,
) -> Result<ExchangeReport, WebSocketLoopbackError> {
    let mut stream = TcpStream::connect(listen_addr)
        .map_err(|source| io_error("connect to loopback WebSocket fixture server", source))?;
    configure_stream(&stream)?;
    if connect_write_delay_ms > 0 {
        thread::sleep(std::time::Duration::from_millis(connect_write_delay_ms));
    }

    let request = upgrade_request(connection_index);
    write_in_chunks(
        &mut stream,
        &request,
        traffic.write_chunks,
        "write WebSocket upgrade request",
    )?;
    let response = read_headers(&mut stream, "read WebSocket upgrade response")?;
    validate_upgrade_response(&response)?;
    let frame = read_frame(&mut stream, traffic.frame_payload_bytes)?;
    validate_text_frame(&frame, connection_index, traffic.frame_payload_bytes)?;
    delay_after_exchange(post_exchange_delay_ms);
    Ok(ExchangeReport {
        bytes_written: request.len(),
        bytes_read: response.len() + frame.len(),
    })
}

fn serve_websocket(
    listener: TcpListener,
    traffic: WebSocketTrafficConfig,
    post_exchange_delay_ms: u64,
) -> Result<ExchangeReport, WebSocketLoopbackError> {
    let mut bytes_read = 0usize;
    let mut bytes_written = 0usize;
    for connection_index in 0..traffic.connections {
        let (mut stream, _) = accept_with_timeout(&listener)?;
        configure_stream(&stream)?;
        let request = read_headers(&mut stream, "read WebSocket upgrade request")?;
        validate_upgrade_request(&request, connection_index)?;
        let response = upgrade_response();
        let frame = text_frame(connection_index, traffic.frame_payload_bytes);
        stream
            .write_all(&response)
            .map_err(|source| io_error("write WebSocket upgrade response", source))?;
        write_in_chunks(
            &mut stream,
            &frame,
            traffic.write_chunks,
            "write WebSocket text frame",
        )?;
        delay_after_exchange(post_exchange_delay_ms);
        bytes_read = bytes_read.saturating_add(request.len());
        bytes_written = bytes_written.saturating_add(response.len() + frame.len());
    }
    Ok(ExchangeReport {
        bytes_read,
        bytes_written,
    })
}

pub(super) fn validate_traffic_config(
    config: &WebSocketTrafficConfig,
) -> Result<(), WebSocketLoopbackError> {
    if config.connections == 0 || config.connections > MAX_CONNECTIONS {
        return Err(WebSocketLoopbackError::InvalidConfig(format!(
            "connections must be in 1..={MAX_CONNECTIONS}"
        )));
    }
    if config.frame_payload_bytes > MAX_FRAME_PAYLOAD_BYTES {
        return Err(WebSocketLoopbackError::InvalidConfig(format!(
            "frame-payload-bytes must be <= {MAX_FRAME_PAYLOAD_BYTES}"
        )));
    }
    if config.write_chunks == 0 || config.write_chunks > MAX_WRITE_CHUNKS {
        return Err(WebSocketLoopbackError::InvalidConfig(format!(
            "write-chunks must be in 1..={MAX_WRITE_CHUNKS}"
        )));
    }
    Ok(())
}

fn upgrade_request(connection_index: usize) -> Vec<u8> {
    format!(
        "GET {REQUEST_TARGET} HTTP/1.1\r\n\
         Host: websocket.e2e.test\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Key: {RFC_SAMPLE_WEBSOCKET_KEY}\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\
         X-Traffic-Probe-E2E-WebSocket: {connection_index}\r\n\
         \r\n"
    )
    .into_bytes()
}

fn upgrade_response() -> Vec<u8> {
    format!(
        "HTTP/1.1 101 Switching Protocols\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Accept: {RFC_SAMPLE_WEBSOCKET_ACCEPT}\r\n\
         Sec-WebSocket-Protocol: {SUBPROTOCOL}\r\n\
         \r\n"
    )
    .into_bytes()
}

fn text_frame(connection_index: usize, payload_bytes: usize) -> Vec<u8> {
    let payload = deterministic_payload(connection_index, payload_bytes);
    let len = u8::try_from(payload.len()).expect("payload is validated as short frame");
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.push(0x81);
    frame.push(len);
    frame.extend_from_slice(&payload);
    frame
}

fn deterministic_payload(connection_index: usize, payload_bytes: usize) -> Vec<u8> {
    if payload_bytes == 2 {
        return b"hi".to_vec();
    }
    let pattern = format!("traffic-probe-websocket-{connection_index}-");
    let pattern = pattern.as_bytes();
    let mut payload = Vec::with_capacity(payload_bytes);
    while payload.len() < payload_bytes {
        let remaining = payload_bytes - payload.len();
        let take = remaining.min(pattern.len());
        payload.extend_from_slice(&pattern[..take]);
    }
    payload
}

fn read_headers(
    stream: &mut TcpStream,
    action: &'static str,
) -> Result<Vec<u8>, WebSocketLoopbackError> {
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while headers.len() < HEADER_READ_LIMIT {
        stream
            .read_exact(&mut byte)
            .map_err(|source| io_error(action, source))?;
        headers.push(byte[0]);
        if headers.ends_with(b"\r\n\r\n") {
            return Ok(headers);
        }
    }
    Err(WebSocketLoopbackError::InvalidMessage(format!(
        "{action} exceeded {HEADER_READ_LIMIT} bytes before header terminator"
    )))
}

fn read_frame(
    stream: &mut TcpStream,
    expected_payload_bytes: usize,
) -> Result<Vec<u8>, WebSocketLoopbackError> {
    let mut frame = vec![0_u8; 2 + expected_payload_bytes];
    stream
        .read_exact(&mut frame)
        .map_err(|source| io_error("read WebSocket text frame", source))?;
    Ok(frame)
}

fn validate_upgrade_request(
    bytes: &[u8],
    connection_index: usize,
) -> Result<(), WebSocketLoopbackError> {
    let message = utf8_message(bytes)?;
    if !message.starts_with(&format!("GET {REQUEST_TARGET} HTTP/1.1")) {
        return Err(WebSocketLoopbackError::InvalidMessage(
            "upgrade request target mismatch".to_string(),
        ));
    }
    for expected in [
        "Connection: Upgrade",
        "Upgrade: websocket",
        &format!("Sec-WebSocket-Key: {RFC_SAMPLE_WEBSOCKET_KEY}"),
        "Sec-WebSocket-Version: 13",
        &format!("Sec-WebSocket-Protocol: {SUBPROTOCOL}"),
        &format!("X-Traffic-Probe-E2E-WebSocket: {connection_index}"),
    ] {
        if !message.contains(expected) {
            return Err(WebSocketLoopbackError::InvalidMessage(format!(
                "upgrade request omitted {expected}"
            )));
        }
    }
    Ok(())
}

fn validate_upgrade_response(bytes: &[u8]) -> Result<(), WebSocketLoopbackError> {
    let message = utf8_message(bytes)?;
    if !message.starts_with("HTTP/1.1 101 Switching Protocols") {
        return Err(WebSocketLoopbackError::InvalidMessage(
            "upgrade response status mismatch".to_string(),
        ));
    }
    for expected in [
        "Connection: Upgrade",
        "Upgrade: websocket",
        &format!("Sec-WebSocket-Accept: {RFC_SAMPLE_WEBSOCKET_ACCEPT}"),
        &format!("Sec-WebSocket-Protocol: {SUBPROTOCOL}"),
    ] {
        if !message.contains(expected) {
            return Err(WebSocketLoopbackError::InvalidMessage(format!(
                "upgrade response omitted {expected}"
            )));
        }
    }
    Ok(())
}

fn validate_text_frame(
    frame: &[u8],
    connection_index: usize,
    payload_bytes: usize,
) -> Result<(), WebSocketLoopbackError> {
    let expected_payload = deterministic_payload(connection_index, payload_bytes);
    if frame.len() != 2 + expected_payload.len()
        || frame.first() != Some(&0x81)
        || frame.get(1) != Some(&(u8::try_from(expected_payload.len()).unwrap_or(u8::MAX)))
        || frame.get(2..) != Some(expected_payload.as_slice())
    {
        return Err(WebSocketLoopbackError::InvalidMessage(
            "text frame payload mismatch".to_string(),
        ));
    }
    Ok(())
}

fn write_in_chunks(
    stream: &mut TcpStream,
    bytes: &[u8],
    chunks: usize,
    action: &'static str,
) -> Result<(), WebSocketLoopbackError> {
    let chunk_size = bytes.len().div_ceil(chunks).max(1);
    for chunk in bytes.chunks(chunk_size) {
        stream
            .write_all(chunk)
            .map_err(|source| io_error(action, source))?;
    }
    Ok(())
}

fn utf8_message(bytes: &[u8]) -> Result<&str, WebSocketLoopbackError> {
    std::str::from_utf8(bytes)
        .map_err(|error| WebSocketLoopbackError::InvalidMessage(error.to_string()))
}

fn io_error(action: &'static str, source: io::Error) -> WebSocketLoopbackError {
    WebSocketLoopbackError::Io { action, source }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn websocket_loopback_fixture_runs_upgrade_and_text_frame() -> Result<(), Box<dyn Error>> {
        let report = run_websocket_loopback(WebSocketLoopbackConfig {
            traffic: WebSocketTrafficConfig {
                connections: 2,
                frame_payload_bytes: 2,
                write_chunks: 2,
            },
            run: LoopbackRunOptions::default(),
        })?;

        assert_eq!(report.connections, 2);
        assert_eq!(report.write_chunks, 2);
        assert_eq!(report.frame_payload_bytes, 2);
        assert_eq!(report.client_bytes_written, report.server_bytes_read);
        assert_eq!(report.client_bytes_read, report.server_bytes_written);
        assert!(report.client_bytes_written > 0);
        assert!(report.client_bytes_read > 0);
        Ok(())
    }

    #[test]
    fn websocket_loopback_rejects_long_frame_payload() {
        let error = run_websocket_loopback(WebSocketLoopbackConfig {
            traffic: WebSocketTrafficConfig {
                connections: 1,
                frame_payload_bytes: MAX_FRAME_PAYLOAD_BYTES + 1,
                write_chunks: 1,
            },
            run: LoopbackRunOptions::default(),
        })
        .expect_err("oversized fixture frame must fail");

        assert!(error.to_string().contains("frame-payload-bytes"));
    }
}
