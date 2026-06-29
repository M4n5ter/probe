use std::io::{Read, Write};

use serde::Serialize;

use crate::{MitmProxyError, error::io_error};

#[derive(Debug)]
pub(crate) struct HttpMessage {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) body: Vec<u8>,
    pub(crate) raw: Vec<u8>,
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
        body: raw[body_start..body_end].to_vec(),
        raw,
    }))
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
    let mut values = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.as_str());
    let Some(value) = values.next() else {
        return Ok(0);
    };
    if values.any(|other| other != value) {
        return Err(MitmProxyError::Http(
            "conflicting Content-Length headers".to_string(),
        ));
    }
    value
        .parse::<usize>()
        .map_err(|error| MitmProxyError::Http(format!("invalid Content-Length: {error}")))
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
}
