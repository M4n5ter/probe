use std::{
    io::{self, Read, Write},
    net::TcpStream,
};

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct HttpJsonRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

pub fn read_request(stream: &mut TcpStream) -> io::Result<HttpJsonRequest> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        if complete_http_request_len(&buffer)?.is_some_and(|expected| buffer.len() >= expected) {
            break;
        }
    }
    let Some(header_end) = find_header_end(&buffer) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted header terminator",
        ));
    };
    let head = parse_http_head(&buffer[..header_end])?;
    let content_length = parse_content_length(&buffer[..header_end])?;
    let body_start = header_end + b"\r\n\r\n".len();
    let body_end = body_start + content_length;
    if buffer.len() < body_end {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "HTTP request body ended before Content-Length",
        ));
    }
    let body = serde_json::from_slice(&buffer[body_start..body_end])
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok(HttpJsonRequest {
        method: head.method,
        path: head.path,
        headers: head.headers,
        body,
    })
}

pub fn write_response(stream: &mut TcpStream, status: u16, body: &Value) -> io::Result<()> {
    let body = serde_json::to_vec(body).map_err(io::Error::other)?;
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Error",
    };
    write!(
        stream,
        "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(&body)?;
    stream.flush()
}

fn complete_http_request_len(buffer: &[u8]) -> io::Result<Option<usize>> {
    let Some(header_end) = find_header_end(buffer) else {
        return Ok(None);
    };
    let content_length = parse_content_length(&buffer[..header_end])?;
    Ok(Some(header_end + b"\r\n\r\n".len() + content_length))
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

struct ParsedHttpHead {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
}

fn parse_http_head(head: &[u8]) -> io::Result<ParsedHttpHead> {
    let head = std::str::from_utf8(head)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut lines = head.lines();
    let Some(line) = lines.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted request line",
        ));
    };
    let mut parts = line.split_whitespace();
    let Some(method) = parts.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted method",
        ));
    };
    let Some(path) = parts.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted path",
        ));
    };
    if parts.next().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted version",
        ));
    }
    let headers = lines
        .filter_map(|line| {
            line.split_once(':')
                .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        })
        .collect::<Vec<_>>();
    Ok(ParsedHttpHead {
        method: method.to_string(),
        path: path.to_string(),
        headers,
    })
}

fn parse_content_length(head: &[u8]) -> io::Result<usize> {
    let head = std::str::from_utf8(head)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    let mut lengths = head.lines().filter_map(|line| {
        line.split_once(':').and_then(|(name, value)| {
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim())
        })
    });
    let Some(raw) = lengths.next() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request omitted Content-Length",
        ));
    };
    if lengths.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request included duplicate Content-Length",
        ));
    }
    raw.parse::<usize>()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}
