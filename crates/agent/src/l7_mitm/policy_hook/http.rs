use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

use runtime::TransparentInterceptionMitmPolicyHookEndpointPlan;

use super::L7MitmPolicyHookError;

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;

pub(super) struct HttpJsonEndpoint {
    pub(super) address: SocketAddr,
    authority: String,
    path_and_query: String,
}

impl HttpJsonEndpoint {
    pub(super) fn from_plan(endpoint: &TransparentInterceptionMitmPolicyHookEndpointPlan) -> Self {
        Self {
            address: endpoint.address,
            authority: endpoint.authority.clone(),
            path_and_query: endpoint.path_and_query.clone(),
        }
    }
}

#[derive(Debug)]
pub(super) struct HttpJsonHookHttpResponse {
    pub(super) status: u16,
    pub(super) body: Vec<u8>,
}

pub(super) fn write_hook_request(
    stream: &mut TcpStream,
    endpoint: &HttpJsonEndpoint,
    payload: &[u8],
    deadline: &HookDeadline,
) -> Result<(), L7MitmPolicyHookError> {
    let head = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nAccept: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        endpoint.path_and_query,
        endpoint.authority,
        payload.len()
    );
    write_all_with_deadline(stream, head.as_bytes(), deadline)?;
    write_all_with_deadline(stream, payload, deadline)?;
    deadline.set_write_timeout(stream)?;
    stream.flush()?;
    Ok(())
}

pub(super) fn read_hook_response(
    mut stream: TcpStream,
    max_response_bytes: usize,
    deadline: &HookDeadline,
) -> Result<HttpJsonHookHttpResponse, L7MitmPolicyHookError> {
    let ResponseHead {
        status,
        body_framing,
        prefetched_body,
    } = read_response_head(&mut stream, deadline)?;
    let body = read_response_body(
        &mut stream,
        prefetched_body,
        body_framing,
        max_response_bytes,
        deadline,
    )?;
    Ok(HttpJsonHookHttpResponse { status, body })
}

#[derive(Debug)]
struct ResponseHead {
    status: u16,
    body_framing: ResponseBodyFraming,
    prefetched_body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseBodyFraming {
    ContentLength(usize),
    Chunked,
}

fn read_response_head(
    stream: &mut TcpStream,
    deadline: &HookDeadline,
) -> Result<ResponseHead, L7MitmPolicyHookError> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 512];
    loop {
        if let Some(header_end) = find_header_terminator(&buffer) {
            if header_end > MAX_RESPONSE_HEADER_BYTES {
                return Err(L7MitmPolicyHookError::InvalidResponse(format!(
                    "response headers exceeded {MAX_RESPONSE_HEADER_BYTES} bytes"
                )));
            }
            let head = parse_response_head(&buffer[..header_end])?;
            return Ok(ResponseHead {
                status: head.status,
                body_framing: head.body_framing,
                prefetched_body: buffer[header_end + 4..].to_vec(),
            });
        }
        if buffer.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(L7MitmPolicyHookError::InvalidResponse(format!(
                "response headers exceeded {MAX_RESPONSE_HEADER_BYTES} bytes"
            )));
        }
        deadline.set_read_timeout(stream)?;
        let bytes_read = stream.read(&mut chunk)?;
        if bytes_read == 0 {
            return Err(L7MitmPolicyHookError::InvalidResponse(
                "response ended before header terminator".to_string(),
            ));
        }
        buffer.extend_from_slice(&chunk[..bytes_read]);
    }
}

fn read_response_body(
    stream: &mut TcpStream,
    prefetched_body: Vec<u8>,
    body_framing: ResponseBodyFraming,
    max_response_bytes: usize,
    deadline: &HookDeadline,
) -> Result<Vec<u8>, L7MitmPolicyHookError> {
    match body_framing {
        ResponseBodyFraming::ContentLength(content_length) => read_content_length_response_body(
            stream,
            prefetched_body,
            content_length,
            max_response_bytes,
            deadline,
        ),
        ResponseBodyFraming::Chunked => {
            read_chunked_response_body(stream, prefetched_body, max_response_bytes, deadline)
        }
    }
}

fn read_content_length_response_body(
    stream: &mut TcpStream,
    prefetched_body: Vec<u8>,
    content_length: usize,
    max_response_bytes: usize,
    deadline: &HookDeadline,
) -> Result<Vec<u8>, L7MitmPolicyHookError> {
    if content_length > max_response_bytes {
        return Err(L7MitmPolicyHookError::ResponseTooLarge {
            limit: max_response_bytes,
        });
    }
    let mut body = Vec::with_capacity(content_length);
    body.extend_from_slice(&prefetched_body[..prefetched_body.len().min(content_length)]);
    let mut chunk = [0_u8; 512];
    while body.len() < content_length {
        deadline.set_read_timeout(stream)?;
        let remaining = content_length - body.len();
        let read_capacity = remaining.min(chunk.len());
        let bytes_read = stream.read(&mut chunk[..read_capacity])?;
        if bytes_read == 0 {
            return Err(L7MitmPolicyHookError::InvalidResponse(
                "response ended before body was complete".to_string(),
            ));
        }
        body.extend_from_slice(&chunk[..bytes_read]);
    }
    Ok(body)
}

fn read_chunked_response_body(
    stream: &mut TcpStream,
    prefetched_body: Vec<u8>,
    max_response_bytes: usize,
    deadline: &HookDeadline,
) -> Result<Vec<u8>, L7MitmPolicyHookError> {
    let mut pending = prefetched_body;
    let mut body = Vec::new();
    loop {
        let size_line = read_chunk_line(stream, &mut pending, deadline)?;
        let chunk_size = parse_chunk_size(&size_line)?;
        if chunk_size == 0 {
            read_chunk_trailers(stream, &mut pending, deadline)?;
            return Ok(body);
        }
        if body.len().saturating_add(chunk_size) > max_response_bytes {
            return Err(L7MitmPolicyHookError::ResponseTooLarge {
                limit: max_response_bytes,
            });
        }
        read_chunk_data(stream, &mut pending, &mut body, chunk_size, deadline)?;
        read_expected_crlf(stream, &mut pending, deadline)?;
    }
}

fn read_chunk_line(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
    deadline: &HookDeadline,
) -> Result<Vec<u8>, L7MitmPolicyHookError> {
    loop {
        if let Some(line_end) = pending.windows(2).position(|window| window == b"\r\n") {
            if line_end > MAX_CHUNK_LINE_BYTES {
                return Err(L7MitmPolicyHookError::InvalidResponse(format!(
                    "chunk line exceeded {MAX_CHUNK_LINE_BYTES} bytes"
                )));
            }
            let line = pending[..line_end].to_vec();
            pending.drain(..line_end + 2);
            return Ok(line);
        }
        if pending.len() > MAX_CHUNK_LINE_BYTES {
            return Err(L7MitmPolicyHookError::InvalidResponse(format!(
                "chunk line exceeded {MAX_CHUNK_LINE_BYTES} bytes"
            )));
        }
        read_more(stream, pending, deadline)?;
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, L7MitmPolicyHookError> {
    let line = std::str::from_utf8(line).map_err(|error| {
        L7MitmPolicyHookError::InvalidResponse(format!("chunk size line is not UTF-8: {error}"))
    })?;
    let size = line.split_once(';').map_or(line, |(size, _)| size).trim();
    if size.is_empty() {
        return Err(L7MitmPolicyHookError::InvalidResponse(
            "empty chunk size".to_string(),
        ));
    }
    usize::from_str_radix(size, 16).map_err(|error| {
        L7MitmPolicyHookError::InvalidResponse(format!("invalid chunk size: {error}"))
    })
}

fn read_chunk_data(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
    body: &mut Vec<u8>,
    mut remaining: usize,
    deadline: &HookDeadline,
) -> Result<(), L7MitmPolicyHookError> {
    while remaining > 0 {
        if pending.is_empty() {
            read_more(stream, pending, deadline)?;
        }
        let taken = remaining.min(pending.len());
        body.extend_from_slice(&pending[..taken]);
        pending.drain(..taken);
        remaining -= taken;
    }
    Ok(())
}

fn read_expected_crlf(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
    deadline: &HookDeadline,
) -> Result<(), L7MitmPolicyHookError> {
    while pending.len() < 2 {
        read_more(stream, pending, deadline)?;
    }
    if pending[..2] != *b"\r\n" {
        return Err(L7MitmPolicyHookError::InvalidResponse(
            "chunk data was not followed by CRLF".to_string(),
        ));
    }
    pending.drain(..2);
    Ok(())
}

fn read_chunk_trailers(
    stream: &mut TcpStream,
    pending: &mut Vec<u8>,
    deadline: &HookDeadline,
) -> Result<(), L7MitmPolicyHookError> {
    let mut trailer_bytes = 0_usize;
    loop {
        let line = read_chunk_line(stream, pending, deadline)?;
        trailer_bytes = trailer_bytes.saturating_add(line.len() + 2);
        if trailer_bytes > MAX_RESPONSE_HEADER_BYTES {
            return Err(L7MitmPolicyHookError::InvalidResponse(format!(
                "chunk trailers exceeded {MAX_RESPONSE_HEADER_BYTES} bytes"
            )));
        }
        if line.is_empty() {
            return Ok(());
        }
    }
}

fn read_more(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    deadline: &HookDeadline,
) -> Result<(), L7MitmPolicyHookError> {
    let mut chunk = [0_u8; 512];
    deadline.set_read_timeout(stream)?;
    let bytes_read = stream.read(&mut chunk)?;
    if bytes_read == 0 {
        return Err(L7MitmPolicyHookError::InvalidResponse(
            "response ended before chunked body was complete".to_string(),
        ));
    }
    buffer.extend_from_slice(&chunk[..bytes_read]);
    Ok(())
}

fn find_header_terminator(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

#[derive(Debug, PartialEq, Eq)]
struct ParsedResponseHead {
    status: u16,
    body_framing: ResponseBodyFraming,
}

fn parse_response_head(head: &[u8]) -> Result<ParsedResponseHead, L7MitmPolicyHookError> {
    let head = std::str::from_utf8(head).map_err(|error| {
        L7MitmPolicyHookError::InvalidResponse(format!("response headers are not UTF-8: {error}"))
    })?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| L7MitmPolicyHookError::InvalidResponse("missing status line".to_string()))?;
    let status = parse_status(status_line)?;
    let mut content_length = None;
    let mut transfer_encodings = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(L7MitmPolicyHookError::InvalidResponse(format!(
                "malformed response header: {line}"
            )));
        };
        if name.eq_ignore_ascii_case("transfer-encoding") {
            transfer_encodings.extend(
                value
                    .split(',')
                    .map(str::trim)
                    .filter(|encoding| !encoding.is_empty())
                    .map(str::to_ascii_lowercase),
            );
        }
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(L7MitmPolicyHookError::InvalidResponse(
                    "duplicate Content-Length".to_string(),
                ));
            }
            content_length = Some(value.trim().parse::<usize>().map_err(|error| {
                L7MitmPolicyHookError::InvalidResponse(format!("invalid Content-Length: {error}"))
            })?);
        }
    }
    if !transfer_encodings.is_empty() {
        if content_length.is_some() {
            return Err(L7MitmPolicyHookError::InvalidResponse(
                "Content-Length with Transfer-Encoding is ambiguous".to_string(),
            ));
        }
        if transfer_encodings.as_slice() == ["chunked"] {
            return Ok(ParsedResponseHead {
                status,
                body_framing: ResponseBodyFraming::Chunked,
            });
        }
        return Err(L7MitmPolicyHookError::InvalidResponse(format!(
            "unsupported Transfer-Encoding: {}",
            transfer_encodings.join(", ")
        )));
    }
    Ok(ParsedResponseHead {
        status,
        body_framing: ResponseBodyFraming::ContentLength(content_length.ok_or_else(|| {
            L7MitmPolicyHookError::InvalidResponse(
                "missing Content-Length or Transfer-Encoding: chunked".to_string(),
            )
        })?),
    })
}

fn parse_status(status_line: &str) -> Result<u16, L7MitmPolicyHookError> {
    let mut parts = status_line.split_whitespace();
    let version = parts.next();
    let status = parts.next();
    if version != Some("HTTP/1.1") && version != Some("HTTP/1.0") {
        return Err(L7MitmPolicyHookError::InvalidResponse(
            "status line must start with HTTP/1.1 or HTTP/1.0".to_string(),
        ));
    }
    status
        .ok_or_else(|| L7MitmPolicyHookError::InvalidResponse("missing status code".to_string()))?
        .parse::<u16>()
        .map_err(|error| {
            L7MitmPolicyHookError::InvalidResponse(format!("invalid status code: {error}"))
        })
}

pub(super) struct HookDeadline {
    expires_at: Instant,
}

impl HookDeadline {
    pub(super) fn after(timeout: Duration) -> Self {
        Self {
            expires_at: Instant::now()
                .checked_add(timeout)
                .expect("validated timeout must fit Instant"),
        }
    }

    pub(super) fn remaining(&self) -> Result<Duration, L7MitmPolicyHookError> {
        self.expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(L7MitmPolicyHookError::Timeout)
    }

    fn set_read_timeout(&self, stream: &TcpStream) -> Result<(), L7MitmPolicyHookError> {
        stream.set_read_timeout(Some(self.remaining()?))?;
        Ok(())
    }

    fn set_write_timeout(&self, stream: &TcpStream) -> Result<(), L7MitmPolicyHookError> {
        stream.set_write_timeout(Some(self.remaining()?))?;
        Ok(())
    }
}

fn write_all_with_deadline(
    stream: &mut TcpStream,
    mut bytes: &[u8],
    deadline: &HookDeadline,
) -> Result<(), L7MitmPolicyHookError> {
    while !bytes.is_empty() {
        deadline.set_write_timeout(stream)?;
        match stream.write(bytes) {
            Ok(0) => {
                return Err(L7MitmPolicyHookError::Io(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write MITM policy hook request",
                )));
            }
            Ok(written) => bytes = &bytes[written..],
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        io::Write,
        net::{TcpListener, TcpStream},
        thread,
        time::Duration,
    };

    use super::*;

    #[test]
    fn response_limit_applies_to_content_length_body() -> Result<(), Box<dyn std::error::Error>> {
        let error = read_server_response(
            |stream| write_response(stream, r#"{"outcome":"delegated","reason":"oversized"}"#),
            8,
        )
        .expect_err("body must exceed configured limit");

        assert!(matches!(
            error,
            L7MitmPolicyHookError::ResponseTooLarge { limit: 8 }
        ));
        Ok(())
    }

    #[test]
    fn response_limit_applies_to_chunked_body() -> Result<(), Box<dyn std::error::Error>> {
        let error = read_server_response(
            |stream| {
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n9\r\noversized\r\n0\r\n\r\n",
                )
                .map_err(|error| error.to_string())
            },
            8,
        )
        .expect_err("chunked body must exceed configured limit");

        assert!(matches!(
            error,
            L7MitmPolicyHookError::ResponseTooLarge { limit: 8 }
        ));
        Ok(())
    }

    #[test]
    fn chunked_response_reads_split_chunks_and_trailers() -> Result<(), Box<dyn std::error::Error>>
    {
        let response = read_server_response(
            |stream| {
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .map_err(|error| error.to_string())?;
                stream
                    .write_all(b"5;part=one\r\nhello\r\n")
                    .map_err(|error| error.to_string())?;
                stream
                    .write_all(b"6\r\n world\r\n0\r\nX-Hook: done\r\n\r\n")
                    .map_err(|error| error.to_string())
            },
            64,
        )?;

        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello world");
        Ok(())
    }

    #[test]
    fn chunked_response_rejects_invalid_chunk_size() -> Result<(), Box<dyn std::error::Error>> {
        let error = read_server_response(
            |stream| {
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nzz\r\nbad\r\n0\r\n\r\n",
                )
                .map_err(|error| error.to_string())
            },
            64,
        )
        .expect_err("invalid chunk size must fail");

        assert!(matches!(error, L7MitmPolicyHookError::InvalidResponse(_)));
        Ok(())
    }

    #[test]
    fn chunked_response_rejects_missing_chunk_crlf() -> Result<(), Box<dyn std::error::Error>> {
        let error = read_server_response(
            |stream| {
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc0\r\n\r\n",
                )
                .map_err(|error| error.to_string())
            },
            64,
        )
        .expect_err("chunk data without trailing CRLF must fail");

        assert!(matches!(error, L7MitmPolicyHookError::InvalidResponse(_)));
        Ok(())
    }

    #[test]
    fn chunked_response_rejects_early_eof() -> Result<(), Box<dyn std::error::Error>> {
        let error = read_server_response(
            |stream| {
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n5\r\nhe",
                )
                .map_err(|error| error.to_string())
            },
            64,
        )
        .expect_err("early EOF inside chunk data must fail");

        assert!(matches!(error, L7MitmPolicyHookError::InvalidResponse(_)));
        Ok(())
    }

    #[test]
    fn response_rejects_transfer_encoding_with_content_length() {
        let error = parse_response_head(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: gzip, chunked\r\n",
        )
        .expect_err("ambiguous response framing must be rejected");

        assert!(matches!(error, L7MitmPolicyHookError::InvalidResponse(_)));
    }

    #[test]
    fn response_rejects_unsupported_transfer_encoding() {
        let error = parse_response_head(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n")
            .expect_err("unsupported transfer coding must be rejected");

        assert!(matches!(error, L7MitmPolicyHookError::InvalidResponse(_)));
    }

    #[test]
    fn response_rejects_duplicate_content_length() {
        let error =
            parse_response_head(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 2\r\n")
                .expect_err("duplicate content length must be rejected");

        assert!(matches!(error, L7MitmPolicyHookError::InvalidResponse(_)));
    }

    #[test]
    fn response_rejects_oversized_headers() -> Result<(), Box<dyn std::error::Error>> {
        let error = read_server_response(
            |stream| {
                write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nX-Padding: {}\r\n",
                    "a".repeat(MAX_RESPONSE_HEADER_BYTES)
                )
                .map_err(|error| error.to_string())
            },
            4_096,
        )
        .expect_err("oversized headers must fail before body parsing");

        assert!(matches!(error, L7MitmPolicyHookError::InvalidResponse(_)));
        Ok(())
    }

    fn read_server_response(
        write_server_response: impl FnOnce(&mut TcpStream) -> Result<(), String> + Send + 'static,
        max_response_bytes: usize,
    ) -> Result<HttpJsonHookHttpResponse, L7MitmPolicyHookError> {
        let listener = TcpListener::bind("127.0.0.1:0").expect("test listener should bind");
        let address = listener
            .local_addr()
            .expect("test listener should have address");
        let server = thread::spawn(move || -> Result<(), String> {
            let (mut stream, _) = listener.accept().map_err(|error| error.to_string())?;
            write_server_response(&mut stream)
        });
        let stream = TcpStream::connect(address).expect("test client should connect");
        let result = read_hook_response(stream, max_response_bytes, &test_deadline());
        server
            .join()
            .expect("server thread should not panic")
            .expect("server should write response");
        result
    }

    fn write_response(stream: &mut TcpStream, body: &str) -> Result<(), String> {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        )
        .map_err(|error| error.to_string())
    }

    fn test_deadline() -> HookDeadline {
        HookDeadline::after(Duration::from_secs(1))
    }
}
