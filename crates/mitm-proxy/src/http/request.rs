use std::{io::Read, net::IpAddr};

use crate::MitmProxyError;

use super::common::{
    MAX_CHUNK_LINE_BYTES, MAX_HEADER_BYTES, connection_tokens, error_is_read_timeout,
    find_header_terminator, optional_content_length, parse_chunk_size, parse_header, read_more,
    transfer_encodings,
};

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

    pub(crate) fn explicit_keep_alive(&self) -> bool {
        connection_tokens(&self.headers).any(|token| token.eq_ignore_ascii_case("keep-alive"))
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
    let body_start = header_end + 4;
    let body = match request_body_framing(&head.headers)? {
        RequestBodyFraming::ContentLength(content_length) => read_content_length_message_body(
            stream,
            &mut raw,
            body_start,
            content_length,
            max_bytes,
        )?,
        RequestBodyFraming::Chunked => {
            read_chunked_message_body(stream, &mut raw, body_start, max_bytes)?
        }
    };
    Ok(Some(HttpMessage {
        method: head.method,
        path: head.path,
        headers: head.headers,
        body,
        raw,
    }))
}

struct ParsedHead {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

enum RequestBodyFraming {
    ContentLength(usize),
    Chunked,
}

fn read_until_headers_complete(
    stream: &mut impl Read,
    raw: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<(), MitmProxyError> {
    while find_header_terminator(raw).is_none() {
        match read_more(stream, raw, max_bytes) {
            Ok(0) => break,
            Ok(_) => {}
            Err(error) if raw.is_empty() && error_is_read_timeout(&error) => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
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

fn request_body_framing(
    headers: &[(String, String)],
) -> Result<RequestBodyFraming, MitmProxyError> {
    let transfer_encodings = transfer_encodings(headers);
    if !transfer_encodings.is_empty() {
        if optional_content_length(headers)?.is_some() {
            return Err(MitmProxyError::Http(
                "HTTP request has both Content-Length and Transfer-Encoding".to_string(),
            ));
        }
        if transfer_encodings.len() == 1 && transfer_encodings[0] == "chunked" {
            return Ok(RequestBodyFraming::Chunked);
        }
        let encoding = transfer_encodings
            .into_iter()
            .find(|encoding| encoding != "chunked")
            .unwrap_or_else(|| "unknown".to_string());
        return Err(MitmProxyError::Http(format!(
            "unsupported HTTP request Transfer-Encoding {encoding}"
        )));
    }
    Ok(RequestBodyFraming::ContentLength(
        optional_content_length(headers)?.unwrap_or(0),
    ))
}

fn read_content_length_message_body(
    stream: &mut impl Read,
    raw: &mut Vec<u8>,
    body_start: usize,
    content_length: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, MitmProxyError> {
    while raw.len().saturating_sub(body_start) < content_length {
        if read_more(stream, raw, max_bytes)? == 0 {
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
    Ok(raw[body_start..body_end].to_vec())
}

fn read_chunked_message_body(
    stream: &mut impl Read,
    raw: &mut Vec<u8>,
    body_start: usize,
    max_bytes: usize,
) -> Result<Vec<u8>, MitmProxyError> {
    let mut cursor = body_start;
    let mut body = Vec::new();
    loop {
        let line_end = read_message_chunk_line(stream, raw, cursor, max_bytes)?;
        let line = raw[cursor..line_end].to_vec();
        let chunk_size = parse_chunk_size(&line)?;
        cursor = line_end + 2;
        if chunk_size == 0 {
            cursor = read_message_chunk_trailers(stream, raw, cursor, max_bytes)?;
            if raw.len() > cursor {
                return Err(MitmProxyError::Http(
                    "HTTP pipelining or read-ahead after chunked body is not supported".to_string(),
                ));
            }
            return Ok(body);
        }
        let data_end = cursor
            .checked_add(chunk_size)
            .ok_or_else(|| MitmProxyError::Http("HTTP chunk size overflowed".to_string()))?;
        let delimiter_end = data_end
            .checked_add(2)
            .ok_or_else(|| MitmProxyError::Http("HTTP chunk delimiter overflowed".to_string()))?;
        read_until_message_offset(
            stream,
            raw,
            delimiter_end,
            max_bytes,
            "HTTP message ended before chunk data completed",
        )?;
        body.extend_from_slice(&raw[cursor..data_end]);
        if raw[data_end..delimiter_end] != *b"\r\n" {
            return Err(MitmProxyError::Http(
                "HTTP chunk data was not followed by CRLF".to_string(),
            ));
        }
        cursor = delimiter_end;
    }
}

fn read_message_chunk_line(
    stream: &mut impl Read,
    raw: &mut Vec<u8>,
    cursor: usize,
    max_bytes: usize,
) -> Result<usize, MitmProxyError> {
    loop {
        if let Some(line_end) = raw[cursor..]
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|offset| cursor + offset)
        {
            if line_end - cursor > MAX_CHUNK_LINE_BYTES {
                return Err(MitmProxyError::Http(format!(
                    "HTTP chunk line exceeded {MAX_CHUNK_LINE_BYTES} bytes"
                )));
            }
            return Ok(line_end);
        }
        if raw.len().saturating_sub(cursor) > MAX_CHUNK_LINE_BYTES {
            return Err(MitmProxyError::Http(format!(
                "HTTP chunk line exceeded {MAX_CHUNK_LINE_BYTES} bytes"
            )));
        }
        if read_more(stream, raw, max_bytes)? == 0 {
            return Err(MitmProxyError::Http(
                "HTTP message ended before chunk line completed".to_string(),
            ));
        }
    }
}

fn read_message_chunk_trailers(
    stream: &mut impl Read,
    raw: &mut Vec<u8>,
    mut cursor: usize,
    max_bytes: usize,
) -> Result<usize, MitmProxyError> {
    let mut trailer_bytes = 0_usize;
    loop {
        let line_end = read_message_chunk_line(stream, raw, cursor, max_bytes)?;
        trailer_bytes = trailer_bytes.saturating_add(line_end - cursor + 2);
        if trailer_bytes > MAX_HEADER_BYTES {
            return Err(MitmProxyError::Http(format!(
                "HTTP chunk trailers exceeded {MAX_HEADER_BYTES} bytes"
            )));
        }
        if line_end == cursor {
            return Ok(line_end + 2);
        }
        cursor = line_end + 2;
    }
}

fn read_until_message_offset(
    stream: &mut impl Read,
    raw: &mut Vec<u8>,
    required_len: usize,
    max_bytes: usize,
    eof_message: &'static str,
) -> Result<(), MitmProxyError> {
    while raw.len() < required_len {
        if read_more(stream, raw, max_bytes)? == 0 {
            return Err(MitmProxyError::Http(eof_message.to_string()));
        }
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use std::{
        error::Error,
        io::Write,
        net::{Ipv4Addr, Shutdown, TcpListener},
        thread,
        time::Duration,
    };

    use super::*;

    #[test]
    fn fixed_body_close_before_content_length_is_an_error() -> Result<(), Box<dyn Error>> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let target = listener.local_addr()?;
        let writer = thread::spawn(move || -> Result<(), String> {
            let mut stream =
                std::net::TcpStream::connect(target).map_err(|error| error.to_string())?;
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
            let mut stream =
                std::net::TcpStream::connect(target).map_err(|error| error.to_string())?;
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
    fn chunked_request_body_is_decoded_and_raw_is_preserved() -> Result<(), Box<dyn Error>> {
        let raw = b"POST /hook HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n5;part=one\r\nhello\r\n6\r\n world\r\n0\r\nX-Trailer: done\r\n\r\n";
        let mut request = raw.as_slice();
        let message = read_http_message(&mut request, 1024)?.expect("request should parse");

        assert_eq!(message.body, b"hello world");
        assert_eq!(message.raw, raw);
        Ok(())
    }

    #[test]
    fn read_ahead_after_chunked_body_is_rejected() -> Result<(), Box<dyn Error>> {
        let mut request = b"POST /hook HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /next HTTP/1.1\r\n\r\n".as_slice();

        let error = read_http_message(&mut request, 1024)
            .expect_err("read-ahead after chunked body must fail");

        assert!(
            error
                .to_string()
                .contains("HTTP pipelining or read-ahead after chunked body is not supported")
        );
        Ok(())
    }

    #[test]
    fn request_rejects_content_length_with_transfer_encoding() {
        let mut request =
            b"POST /hook HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
                .as_slice();

        let error = read_http_message(&mut request, 1024)
            .expect_err("ambiguous request body framing must fail");

        assert!(
            error
                .to_string()
                .contains("HTTP request has both Content-Length and Transfer-Encoding")
        );
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
}
