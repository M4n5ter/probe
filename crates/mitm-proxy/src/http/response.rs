use std::io::{Read, Write};

use serde::Serialize;

use crate::{MitmProxyError, error::io_error};

use super::{
    common::{
        MAX_CHUNK_LINE_BYTES, MAX_HEADER_BYTES, connection_tokens, find_header_terminator,
        header_values, optional_content_length, parse_chunk_size, parse_header, transfer_encodings,
    },
    request::HttpMessage,
};

const RESPONSE_IO_BUFFER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HttpResponseRelay {
    Http { close_downstream: bool },
    UpgradeTunnel,
}

pub(crate) fn relay_http_response(
    stream: &mut impl Read,
    request: &HttpMessage,
    mut emit: impl FnMut(&[u8]) -> Result<(), MitmProxyError>,
) -> Result<HttpResponseRelay, MitmProxyError> {
    let ResponseHead {
        head,
        mode,
        prefetched_body,
    } = read_response_head(stream, request)?;
    emit(&head)?;
    match mode {
        ResponseRelayMode::UpgradeTunnel => {
            if !prefetched_body.is_empty() {
                emit(&prefetched_body)?;
            }
            Ok(HttpResponseRelay::UpgradeTunnel)
        }
        ResponseRelayMode::Http {
            close_downstream,
            body_framing: ResponseBodyFraming::NoBody,
        } => {
            if prefetched_body.is_empty() {
                Ok(HttpResponseRelay::Http { close_downstream })
            } else {
                Err(MitmProxyError::Http(
                    "HTTP response included a body where none is allowed".to_string(),
                ))
            }
        }
        ResponseRelayMode::Http {
            close_downstream,
            body_framing: ResponseBodyFraming::ContentLength(content_length),
        } => {
            relay_content_length_body(stream, prefetched_body, content_length, emit)?;
            Ok(HttpResponseRelay::Http { close_downstream })
        }
        ResponseRelayMode::Http {
            close_downstream,
            body_framing: ResponseBodyFraming::Chunked,
        } => {
            relay_chunked_body(stream, prefetched_body, emit)?;
            Ok(HttpResponseRelay::Http { close_downstream })
        }
    }
}

pub(crate) fn write_json_response(
    stream: &mut impl Write,
    status: u16,
    body: impl Serialize,
) -> Result<(), MitmProxyError> {
    let body = serde_json::to_vec(&body)?;
    write_simple_response(
        stream,
        simple_response_bytes(status, &body, "application/json"),
    )
}

pub(crate) fn empty_response_bytes(status: u16) -> Vec<u8> {
    simple_response_bytes(status, &[], "application/octet-stream")
}

pub(crate) fn simple_response_bytes(status: u16, body: &[u8], content_type: &str) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {status} {}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status_reason(status),
        body.len()
    );
    let mut response = Vec::with_capacity(head.len() + body.len());
    response.extend_from_slice(head.as_bytes());
    response.extend_from_slice(body);
    response
}

struct ResponseHead {
    head: Vec<u8>,
    mode: ResponseRelayMode,
    prefetched_body: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseRelayMode {
    Http {
        close_downstream: bool,
        body_framing: ResponseBodyFraming,
    },
    UpgradeTunnel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseBodyFraming {
    NoBody,
    ContentLength(usize),
    Chunked,
}

fn read_response_head(
    stream: &mut impl Read,
    request: &HttpMessage,
) -> Result<ResponseHead, MitmProxyError> {
    let mut raw = Vec::new();
    loop {
        if let Some(header_end) = find_header_terminator(&raw) {
            if header_end > MAX_HEADER_BYTES {
                return Err(MitmProxyError::Http(format!(
                    "HTTP response headers exceeded {MAX_HEADER_BYTES} bytes"
                )));
            }
            let head_end = header_end + 4;
            let parsed = parse_response_head(&raw[..header_end], request)?;
            return Ok(ResponseHead {
                head: raw[..head_end].to_vec(),
                mode: parsed.mode,
                prefetched_body: raw[head_end..].to_vec(),
            });
        }
        if raw.len() > MAX_HEADER_BYTES {
            return Err(MitmProxyError::Http(format!(
                "HTTP response headers exceeded {MAX_HEADER_BYTES} bytes"
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
    mode: ResponseRelayMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HttpResponseVersion {
    Http10,
    Http11,
}

struct ParsedStatus {
    version: HttpResponseVersion,
    code: u16,
}

fn parse_response_head(
    bytes: &[u8],
    request: &HttpMessage,
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
    let close_downstream = response_connection_closes(status.version, &headers);
    let mode = if response_switches_protocols(status.code, request, &headers)? {
        ResponseRelayMode::UpgradeTunnel
    } else {
        ResponseRelayMode::Http {
            close_downstream,
            body_framing: response_body_framing(status.code, request.is_head(), &headers)?,
        }
    };
    Ok(ParsedResponseHead { mode })
}

fn parse_status(status_line: &str) -> Result<ParsedStatus, MitmProxyError> {
    let mut parts = status_line.split_whitespace();
    let version = parts
        .next()
        .ok_or_else(|| MitmProxyError::Http("HTTP response version is missing".to_string()))?;
    let version = match version {
        "HTTP/1.0" => HttpResponseVersion::Http10,
        "HTTP/1.1" => HttpResponseVersion::Http11,
        _ => {
            return Err(MitmProxyError::Http(format!(
                "unsupported HTTP response version {version}"
            )));
        }
    };
    let code = parts
        .next()
        .ok_or_else(|| MitmProxyError::Http("HTTP response status code is missing".to_string()))?
        .parse::<u16>()
        .map_err(|error| MitmProxyError::Http(format!("invalid HTTP response status: {error}")))?;
    Ok(ParsedStatus { version, code })
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

fn response_connection_closes(version: HttpResponseVersion, headers: &[(String, String)]) -> bool {
    let mut keep_alive = false;
    for token in connection_tokens(headers) {
        if token.eq_ignore_ascii_case("close") {
            return true;
        }
        if token.eq_ignore_ascii_case("keep-alive") {
            keep_alive = true;
        }
    }
    version == HttpResponseVersion::Http10 && !keep_alive
}

fn response_switches_protocols(
    status: u16,
    request: &HttpMessage,
    headers: &[(String, String)],
) -> Result<bool, MitmProxyError> {
    if status != 101 {
        return Ok(false);
    }
    if !request.requests_protocol_upgrade() {
        return Err(MitmProxyError::Http(
            "HTTP 101 response did not match an Upgrade request".to_string(),
        ));
    }
    if !connection_tokens(headers).any(|token| token.eq_ignore_ascii_case("upgrade"))
        || !header_values(headers, "upgrade").any(|value| !value.trim().is_empty())
    {
        return Err(MitmProxyError::Http(
            "HTTP 101 response omitted Upgrade headers".to_string(),
        ));
    }
    Ok(true)
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
        if trailer_bytes > MAX_HEADER_BYTES {
            return Err(MitmProxyError::Http(format!(
                "HTTP response chunk trailers exceeded {MAX_HEADER_BYTES} bytes"
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

fn write_simple_response(stream: &mut impl Write, response: Vec<u8>) -> Result<(), MitmProxyError> {
    stream
        .write_all(&response)
        .map_err(io_error("write MITM proxy HTTP response"))?;
    stream
        .flush()
        .map_err(io_error("flush MITM proxy HTTP response"))
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
    use std::error::Error;

    use super::*;
    use crate::http::read_http_message;

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

    #[test]
    fn relay_upgrade_response_preserves_prefetched_tunnel_bytes() -> Result<(), Box<dyn Error>> {
        let mut request = b"GET /chat HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".as_slice();
        let request = read_http_message(&mut request, 1024)?.expect("request should parse");
        let raw = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n\x81\x02hi";
        let mut response = raw.as_slice();
        let mut relayed = Vec::new();

        let relay = relay_http_response(&mut response, &request, |bytes| {
            relayed.extend_from_slice(bytes);
            Ok(())
        })?;

        assert_eq!(relay, HttpResponseRelay::UpgradeTunnel);
        assert_eq!(relayed, raw);
        Ok(())
    }
}
