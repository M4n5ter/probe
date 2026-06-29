use std::{
    io::{Read, Write},
    net::IpAddr,
};

use serde::Serialize;

use crate::{MitmProxyError, error::io_error};

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_CHUNK_LINE_BYTES: usize = 8 * 1024;
const RESPONSE_IO_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Debug)]
pub(crate) struct HttpMessage {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) raw: Vec<u8>,
}

impl HttpMessage {
    pub(crate) fn authority(&self) -> Result<Option<&str>, MitmProxyError> {
        let mut hosts = self
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
            .map(|(_, value)| value.as_str());
        let Some(host) = hosts.next() else {
            return Ok(None);
        };
        if hosts.next().is_some() {
            return Err(MitmProxyError::Http(
                "duplicate HTTP Host headers are not supported".to_string(),
            ));
        }
        host_name(host)
            .filter(|host| !host.is_empty())
            .map(Some)
            .ok_or_else(|| MitmProxyError::Http("HTTP Host header is malformed".to_string()))
    }

    pub(crate) fn is_head(&self) -> bool {
        self.method.eq_ignore_ascii_case("HEAD")
    }
}

pub(crate) fn read_http_message(
    stream: &mut impl Read,
    max_bytes: usize,
) -> Result<Option<HttpMessage>, MitmProxyError> {
    let mut raw = Vec::new();
    read_until_headers_complete(stream, &mut raw, max_bytes)?;
    if raw.is_empty() {
        return Ok(None);
    }
    let header_end = find_header_terminator(&raw).ok_or_else(|| {
        MitmProxyError::Http("HTTP message ended before header terminator".to_string())
    })?;
    let head = parse_head(&raw[..header_end])?;
    let content_length = content_length(&head.headers)?;
    let body_start = header_end + 4;
    while raw.len().saturating_sub(body_start) < content_length {
        if read_more(stream, &mut raw, max_bytes)? == 0 {
            return Err(MitmProxyError::Http(
                "HTTP message ended before fixed body completed".to_string(),
            ));
        }
    }
    let body_end = body_start + content_length;
    if raw.len() > body_end {
        return Err(MitmProxyError::Http(
            "HTTP pipelining or read-ahead after the fixed body is not supported".to_string(),
        ));
    }
    Ok(Some(HttpMessage {
        method: head.method,
        path: head.path,
        headers: head.headers,
        body: raw[body_start..body_end].to_vec(),
        raw,
    }))
}

pub(crate) fn relay_http_response(
    stream: &mut impl Read,
    request: &HttpMessage,
    mut emit: impl FnMut(&[u8]) -> Result<(), MitmProxyError>,
) -> Result<(), MitmProxyError> {
    let ResponseHead {
        head,
        body_framing,
        prefetched_body,
    } = read_response_head(stream, request.is_head())?;
    emit(&head)?;
    match body_framing {
        ResponseBodyFraming::NoBody => {
            if prefetched_body.is_empty() {
                Ok(())
            } else {
                Err(MitmProxyError::Http(
                    "HTTP response included a body where none is allowed".to_string(),
                ))
            }
        }
        ResponseBodyFraming::ContentLength(content_length) => {
            relay_content_length_body(stream, prefetched_body, content_length, emit)
        }
        ResponseBodyFraming::Chunked => relay_chunked_body(stream, prefetched_body, emit),
    }
}

pub(crate) fn write_json_response(
    stream: &mut impl Write,
    status: u16,
    body: impl Serialize,
) -> Result<(), MitmProxyError> {
    let body = serde_json::to_vec(&body)?;
    write_response(
        stream,
        status,
        status_reason(status),
        &body,
        "application/json",
    )
}

pub(crate) fn write_empty_response(
    stream: &mut impl Write,
    status: u16,
) -> Result<(), MitmProxyError> {
    write_response(
        stream,
        status,
        status_reason(status),
        &[],
        "application/octet-stream",
    )
}

struct ResponseHead {
    head: Vec<u8>,
    body_framing: ResponseBodyFraming,
    prefetched_body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseBodyFraming {
    NoBody,
    ContentLength(usize),
    Chunked,
}

fn read_response_head(
    stream: &mut impl Read,
    request_is_head: bool,
) -> Result<ResponseHead, MitmProxyError> {
    let mut raw = Vec::new();
    loop {
        if let Some(header_end) = find_header_terminator(&raw) {
            if header_end > MAX_RESPONSE_HEADER_BYTES {
                return Err(MitmProxyError::Http(format!(
                    "HTTP response headers exceeded {MAX_RESPONSE_HEADER_BYTES} bytes"
                )));
            }
            let head_end = header_end + 4;
            let parsed = parse_response_head(&raw[..header_end], request_is_head)?;
            return Ok(ResponseHead {
                head: raw[..head_end].to_vec(),
                body_framing: parsed.body_framing,
                prefetched_body: raw[head_end..].to_vec(),
            });
        }
        if raw.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err(MitmProxyError::Http(format!(
                "HTTP response headers exceeded {MAX_RESPONSE_HEADER_BYTES} bytes"
            )));
        }
        if read_response_more(stream, &mut raw)? == 0 {
            return Err(MitmProxyError::Http(
                "HTTP response ended before header terminator".to_string(),
            ));
        }
    }
}

struct ParsedResponseHead {
    body_framing: ResponseBodyFraming,
}

fn parse_response_head(
    bytes: &[u8],
    request_is_head: bool,
) -> Result<ParsedResponseHead, MitmProxyError> {
    let head = std::str::from_utf8(bytes).map_err(|error| {
        MitmProxyError::Http(format!("HTTP response head is not UTF-8: {error}"))
    })?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| MitmProxyError::Http("HTTP response status line is missing".to_string()))?;
    let status = parse_status(status_line)?;
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(parse_header)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedResponseHead {
        body_framing: response_body_framing(status, request_is_head, &headers)?,
    })
}

fn parse_status(status_line: &str) -> Result<u16, MitmProxyError> {
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| MitmProxyError::Http("HTTP response version is missing".to_string()))?;
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        return Err(MitmProxyError::Http(format!(
            "unsupported HTTP response version {version}"
        )));
    }
    parts
        .next()
        .ok_or_else(|| MitmProxyError::Http("HTTP response status code is missing".to_string()))?
        .parse::<u16>()
        .map_err(|error| MitmProxyError::Http(format!("invalid HTTP response status: {error}")))
}

fn response_body_framing(
    status: u16,
    request_is_head: bool,
    headers: &[(String, String)],
) -> Result<ResponseBodyFraming, MitmProxyError> {
    if request_is_head || (100..200).contains(&status) || status == 204 || status == 304 {
        return Ok(ResponseBodyFraming::NoBody);
    }
    let transfer_encodings = transfer_encodings(headers);
    if !transfer_encodings.is_empty() {
        if optional_content_length(headers)?.is_some() {
            return Err(MitmProxyError::Http(
                "HTTP response has both Content-Length and Transfer-Encoding".to_string(),
            ));
        }
        return match transfer_encodings.last().map(String::as_str) {
            Some("chunked") => Ok(ResponseBodyFraming::Chunked),
            Some(encoding) => Err(MitmProxyError::Http(format!(
                "unsupported HTTP response Transfer-Encoding {encoding}"
            ))),
            None => unreachable!("checked non-empty transfer encodings"),
        };
    }
    Ok(ResponseBodyFraming::ContentLength(
        optional_content_length(headers)?.ok_or_else(|| {
            MitmProxyError::Http(
                "HTTP response missing Content-Length or Transfer-Encoding: chunked".to_string(),
            )
        })?,
    ))
}

fn transfer_encodings(headers: &[(String, String)]) -> Vec<String> {
    headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("transfer-encoding"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|encoding| !encoding.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

fn relay_content_length_body(
    stream: &mut impl Read,
    prefetched_body: Vec<u8>,
    content_length: usize,
    mut emit: impl FnMut(&[u8]) -> Result<(), MitmProxyError>,
) -> Result<(), MitmProxyError> {
    if prefetched_body.len() > content_length {
        return Err(MitmProxyError::Http(
            "HTTP response pipelining or read-ahead after the fixed body is not supported"
                .to_string(),
        ));
    }
    if !prefetched_body.is_empty() {
        emit(&prefetched_body)?;
    }
    let mut remaining = content_length - prefetched_body.len();
    let mut buffer = [0_u8; RESPONSE_IO_BUFFER_BYTES];
    while remaining > 0 {
        let capacity = remaining.min(buffer.len());
        let read = stream
            .read(&mut buffer[..capacity])
            .map_err(io_error("read MITM proxy upstream HTTP response body"))?;
        if read == 0 {
            return Err(MitmProxyError::Http(
                "HTTP response ended before fixed body completed".to_string(),
            ));
        }
        emit(&buffer[..read])?;
        remaining -= read;
    }
    Ok(())
}

fn relay_chunked_body(
    stream: &mut impl Read,
    mut pending: Vec<u8>,
    mut emit: impl FnMut(&[u8]) -> Result<(), MitmProxyError>,
) -> Result<(), MitmProxyError> {
    loop {
        let size_line = read_chunk_line(stream, &mut pending)?;
        emit(&size_line)?;
        emit(b"\r\n")?;
        let chunk_size = parse_chunk_size(&size_line)?;
        if chunk_size == 0 {
            relay_chunk_trailers(stream, &mut pending, emit)?;
            if pending.is_empty() {
                return Ok(());
            }
            return Err(MitmProxyError::Http(
                "HTTP response pipelining or read-ahead after chunked body is not supported"
                    .to_string(),
            ));
        }
        relay_exact_chunk_bytes(stream, &mut pending, chunk_size, &mut emit)?;
        relay_expected_crlf(stream, &mut pending, &mut emit)?;
    }
}

fn read_chunk_line(
    stream: &mut impl Read,
    pending: &mut Vec<u8>,
) -> Result<Vec<u8>, MitmProxyError> {
    loop {
        if let Some(line_end) = pending.windows(2).position(|window| window == b"\r\n") {
            if line_end > MAX_CHUNK_LINE_BYTES {
                return Err(MitmProxyError::Http(format!(
                    "HTTP response chunk line exceeded {MAX_CHUNK_LINE_BYTES} bytes"
                )));
            }
            let line = pending[..line_end].to_vec();
            pending.drain(..line_end + 2);
            return Ok(line);
        }
        if pending.len() > MAX_CHUNK_LINE_BYTES {
            return Err(MitmProxyError::Http(format!(
                "HTTP response chunk line exceeded {MAX_CHUNK_LINE_BYTES} bytes"
            )));
        }
        if read_response_more(stream, pending)? == 0 {
            return Err(MitmProxyError::Http(
                "HTTP response ended before chunk line completed".to_string(),
            ));
        }
    }
}

fn parse_chunk_size(line: &[u8]) -> Result<usize, MitmProxyError> {
    let line = std::str::from_utf8(line)
        .map_err(|error| MitmProxyError::Http(format!("HTTP chunk size is not UTF-8: {error}")))?;
    let size = line.split_once(';').map_or(line, |(size, _)| size).trim();
    if size.is_empty() {
        return Err(MitmProxyError::Http("empty HTTP chunk size".to_string()));
    }
    usize::from_str_radix(size, 16)
        .map_err(|error| MitmProxyError::Http(format!("invalid HTTP chunk size: {error}")))
}

fn relay_exact_chunk_bytes(
    stream: &mut impl Read,
    pending: &mut Vec<u8>,
    mut remaining: usize,
    emit: &mut impl FnMut(&[u8]) -> Result<(), MitmProxyError>,
) -> Result<(), MitmProxyError> {
    while remaining > 0 {
        if pending.is_empty() && read_response_more(stream, pending)? == 0 {
            return Err(MitmProxyError::Http(
                "HTTP response ended before chunk data completed".to_string(),
            ));
        }
        let taken = remaining.min(pending.len());
        emit(&pending[..taken])?;
        pending.drain(..taken);
        remaining -= taken;
    }
    Ok(())
}

fn relay_expected_crlf(
    stream: &mut impl Read,
    pending: &mut Vec<u8>,
    emit: &mut impl FnMut(&[u8]) -> Result<(), MitmProxyError>,
) -> Result<(), MitmProxyError> {
    while pending.len() < 2 {
        if read_response_more(stream, pending)? == 0 {
            return Err(MitmProxyError::Http(
                "HTTP response ended before chunk delimiter completed".to_string(),
            ));
        }
    }
    if pending[..2] != *b"\r\n" {
        return Err(MitmProxyError::Http(
            "HTTP response chunk data was not followed by CRLF".to_string(),
        ));
    }
    emit(b"\r\n")?;
    pending.drain(..2);
    Ok(())
}

fn relay_chunk_trailers(
    stream: &mut impl Read,
    pending: &mut Vec<u8>,
    mut emit: impl FnMut(&[u8]) -> Result<(), MitmProxyError>,
) -> Result<(), MitmProxyError> {
    let mut trailer_bytes = 0_usize;
    loop {
        let line = read_chunk_line(stream, pending)?;
        trailer_bytes = trailer_bytes.saturating_add(line.len() + 2);
        if trailer_bytes > MAX_RESPONSE_HEADER_BYTES {
            return Err(MitmProxyError::Http(format!(
                "HTTP response chunk trailers exceeded {MAX_RESPONSE_HEADER_BYTES} bytes"
            )));
        }
        emit(&line)?;
        emit(b"\r\n")?;
        if line.is_empty() {
            return Ok(());
        }
    }
}

fn read_response_more(
    stream: &mut impl Read,
    buffer: &mut Vec<u8>,
) -> Result<usize, MitmProxyError> {
    let mut chunk = [0_u8; 512];
    let read = stream
        .read(&mut chunk)
        .map_err(io_error("read MITM proxy upstream HTTP response"))?;
    buffer.extend_from_slice(&chunk[..read]);
    Ok(read)
}

fn write_response(
    stream: &mut impl Write,
    status: u16,
    reason: &str,
    body: &[u8],
    content_type: &str,
) -> Result<(), MitmProxyError> {
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream
        .write_all(head.as_bytes())
        .map_err(io_error("write MITM proxy HTTP response head"))?;
    stream
        .write_all(body)
        .map_err(io_error("write MITM proxy HTTP response body"))?;
    stream
        .flush()
        .map_err(io_error("flush MITM proxy HTTP response"))
}

fn read_until_headers_complete(
    stream: &mut impl Read,
    raw: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<(), MitmProxyError> {
    while find_header_terminator(raw).is_none() {
        if read_more(stream, raw, max_bytes)? == 0 {
            break;
        }
    }
    Ok(())
}

fn read_more(
    stream: &mut impl Read,
    raw: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<usize, MitmProxyError> {
    if raw.len() >= max_bytes {
        return Err(MitmProxyError::Http(format!(
            "HTTP message exceeded {max_bytes} bytes"
        )));
    }
    let mut buffer = [0_u8; 1024];
    let capacity = buffer.len().min(max_bytes - raw.len());
    let read = stream
        .read(&mut buffer[..capacity])
        .map_err(io_error("read MITM proxy HTTP message"))?;
    raw.extend_from_slice(&buffer[..read]);
    Ok(read)
}

struct ParsedHead {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

fn parse_head(bytes: &[u8]) -> Result<ParsedHead, MitmProxyError> {
    let head = std::str::from_utf8(bytes)
        .map_err(|error| MitmProxyError::Http(format!("HTTP head is not UTF-8: {error}")))?;
    let mut lines = head.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| MitmProxyError::Http("HTTP request line is missing".to_string()))?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts
        .next()
        .ok_or_else(|| MitmProxyError::Http("HTTP method is missing".to_string()))?;
    let path = request_parts
        .next()
        .ok_or_else(|| MitmProxyError::Http("HTTP target is missing".to_string()))?;
    let version = request_parts
        .next()
        .ok_or_else(|| MitmProxyError::Http("HTTP version is missing".to_string()))?;
    if !version.starts_with("HTTP/1.") {
        return Err(MitmProxyError::Http(format!(
            "unsupported HTTP version {version}"
        )));
    }
    let headers = lines
        .filter(|line| !line.is_empty())
        .map(parse_header)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ParsedHead {
        method: method.to_string(),
        path: path.to_string(),
        headers,
    })
}

fn parse_header(line: &str) -> Result<(String, String), MitmProxyError> {
    let (name, value) = line
        .split_once(':')
        .ok_or_else(|| MitmProxyError::Http(format!("invalid HTTP header line {line:?}")))?;
    Ok((name.trim().to_string(), value.trim().to_string()))
}

fn content_length(headers: &[(String, String)]) -> Result<usize, MitmProxyError> {
    Ok(optional_content_length(headers)?.unwrap_or(0))
}

fn optional_content_length(headers: &[(String, String)]) -> Result<Option<usize>, MitmProxyError> {
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str());
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.any(|other| other != value) {
        return Err(MitmProxyError::Http(
            "conflicting Content-Length headers".to_string(),
        ));
    }
    value
        .parse::<usize>()
        .map_err(|error| MitmProxyError::Http(format!("invalid Content-Length: {error}")))
        .map(Some)
}

fn host_name(value: &str) -> Option<&str> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (host, suffix) = rest.split_once(']')?;
        if host.parse::<IpAddr>().is_err() || !valid_authority_port_suffix(suffix) {
            return None;
        }
        return Some(host);
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if host.contains(':') {
            return None;
        }
        if port.is_empty() || !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        return Some(host);
    }
    Some(value)
}

fn valid_authority_port_suffix(suffix: &str) -> bool {
    suffix.is_empty()
        || suffix
            .strip_prefix(':')
            .is_some_and(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
}

fn find_header_terminator(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn status_reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        io::Write,
        net::{Ipv4Addr, Shutdown, TcpListener, TcpStream},
        thread,
        time::Duration,
    };

    use super::*;

    #[test]
    fn fixed_body_close_before_content_length_is_an_error() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let target = listener.local_addr()?;
        let writer = thread::spawn(move || -> Result<(), String> {
            let mut stream = TcpStream::connect(target).map_err(|error| error.to_string())?;
            stream
                .write_all(b"POST /hook HTTP/1.1\r\nContent-Length: 5\r\n\r\nhe")
                .map_err(|error| error.to_string())?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|error| error.to_string())
        });
        let (mut stream, _peer) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;

        let error = read_http_message(&mut stream, 1024)
            .expect_err("truncated fixed body must fail instead of spinning");

        writer
            .join()
            .map_err(|_| "writer thread panicked")?
            .map_err(std::io::Error::other)?;
        assert!(
            error
                .to_string()
                .contains("HTTP message ended before fixed body completed")
        );
        Ok(())
    }

    #[test]
    fn read_ahead_after_fixed_body_is_rejected() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let target = listener.local_addr()?;
        let writer = thread::spawn(move || -> Result<(), String> {
            let mut stream = TcpStream::connect(target).map_err(|error| error.to_string())?;
            stream
                .write_all(
                    b"POST /hook HTTP/1.1\r\nContent-Length: 2\r\n\r\nheGET /next HTTP/1.1\r\n\r\n",
                )
                .map_err(|error| error.to_string())?;
            stream
                .shutdown(Shutdown::Write)
                .map_err(|error| error.to_string())
        });
        let (mut stream, _peer) = listener.accept()?;
        stream.set_read_timeout(Some(Duration::from_secs(2)))?;

        let error = read_http_message(&mut stream, 1024)
            .expect_err("read-ahead must not be forwarded as part of the first request");

        writer
            .join()
            .map_err(|_| "writer thread panicked")?
            .map_err(std::io::Error::other)?;
        assert!(
            error
                .to_string()
                .contains("HTTP pipelining or read-ahead after the fixed body is not supported")
        );
        Ok(())
    }

    #[test]
    fn http_message_extracts_host_name_without_port() -> Result<(), Box<dyn Error>> {
        let mut request = b"GET / HTTP/1.1\r\nHost: example.test:8443\r\n\r\n".as_slice();
        let message = read_http_message(&mut request, 1024)?.expect("request should parse");

        assert_eq!(message.authority()?, Some("example.test"));
        Ok(())
    }

    #[test]
    fn http_message_extracts_bracketed_ipv6_host() -> Result<(), Box<dyn Error>> {
        let mut request = b"GET / HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n".as_slice();
        let message = read_http_message(&mut request, 1024)?.expect("request should parse");

        assert_eq!(message.authority()?, Some("::1"));
        Ok(())
    }

    #[test]
    fn authority_rejects_duplicate_host_headers() -> Result<(), Box<dyn Error>> {
        let mut request =
            b"GET / HTTP/1.1\r\nHost: first.test\r\nHost: second.test\r\n\r\n".as_slice();
        let message = read_http_message(&mut request, 1024)?.expect("request should parse");

        let error = message
            .authority()
            .expect_err("duplicate Host headers must be rejected");

        assert!(error.to_string().contains("duplicate HTTP Host"));
        Ok(())
    }

    #[test]
    fn authority_rejects_malformed_host_header() -> Result<(), Box<dyn Error>> {
        for host in [
            "[example.test]:443",
            "[::1]junk",
            "[::1]:bad",
            "example.test:bad",
        ] {
            let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n");
            let mut request = request.as_bytes();
            let message = read_http_message(&mut request, 1024)?.expect("request should parse");

            let error = message
                .authority()
                .expect_err("malformed Host must be rejected");

            assert!(error.to_string().contains("HTTP Host header is malformed"));
        }
        Ok(())
    }

    #[test]
    fn relay_response_uses_content_length_boundary() -> Result<(), Box<dyn Error>> {
        let mut request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice();
        let request = read_http_message(&mut request, 1024)?.expect("request should parse");
        let mut response = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".as_slice();
        let mut relayed = Vec::new();

        relay_http_response(&mut response, &request, |bytes| {
            relayed.extend_from_slice(bytes);
            Ok(())
        })?;

        assert_eq!(
            relayed,
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        );
        Ok(())
    }

    #[test]
    fn relay_response_preserves_chunked_boundary() -> Result<(), Box<dyn Error>> {
        let mut request = b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n".as_slice();
        let request = read_http_message(&mut request, 1024)?.expect("request should parse");
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-Test: done\r\n\r\n";
        let mut response = raw.as_slice();
        let mut relayed = Vec::new();

        relay_http_response(&mut response, &request, |bytes| {
            relayed.extend_from_slice(bytes);
            Ok(())
        })?;

        assert_eq!(relayed, raw);
        Ok(())
    }
}
