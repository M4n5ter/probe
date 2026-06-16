use std::{
    error::Error,
    fmt,
    io::{self, Read},
};

const MAX_REQUESTS: usize = 1024;
const MAX_BODY_BYTES: usize = 1024 * 1024;
const MAX_WRITE_CHUNKS: usize = 1024;
const HTTP_READ_CHUNK: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HttpTrafficConfig {
    pub requests: usize,
    pub request_body_bytes: usize,
    pub response_body_bytes: usize,
    pub write_chunks: usize,
}

impl Default for HttpTrafficConfig {
    fn default() -> Self {
        Self {
            requests: 1,
            request_body_bytes: 64,
            response_body_bytes: 32,
            write_chunks: 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ExchangeReport {
    pub bytes_written: usize,
    pub bytes_read: usize,
}

#[derive(Debug)]
pub(crate) enum HttpMessageError {
    InvalidConfig(String),
    InvalidMessage(String),
    Io {
        action: &'static str,
        source: io::Error,
    },
}

impl fmt::Display for HttpMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidConfig(reason) => write!(formatter, "invalid HTTP config: {reason}"),
            Self::InvalidMessage(reason) => write!(formatter, "invalid HTTP message: {reason}"),
            Self::Io { action, source } => write!(formatter, "failed to {action}: {source}"),
        }
    }
}

impl Error for HttpMessageError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::InvalidConfig(_) | Self::InvalidMessage(_) => None,
        }
    }
}

pub(crate) fn validate_traffic_config(config: &HttpTrafficConfig) -> Result<(), HttpMessageError> {
    if config.requests == 0 || config.requests > MAX_REQUESTS {
        return Err(HttpMessageError::InvalidConfig(format!(
            "requests must be in 1..={MAX_REQUESTS}"
        )));
    }
    if config.request_body_bytes > MAX_BODY_BYTES {
        return Err(HttpMessageError::InvalidConfig(format!(
            "request-body-bytes must be <= {MAX_BODY_BYTES}"
        )));
    }
    if config.response_body_bytes > MAX_BODY_BYTES {
        return Err(HttpMessageError::InvalidConfig(format!(
            "response-body-bytes must be <= {MAX_BODY_BYTES}"
        )));
    }
    if config.write_chunks == 0 || config.write_chunks > MAX_WRITE_CHUNKS {
        return Err(HttpMessageError::InvalidConfig(format!(
            "write-chunks must be in 1..={MAX_WRITE_CHUNKS}"
        )));
    }
    Ok(())
}

pub(crate) fn request(request_index: usize, body_bytes: usize) -> Vec<u8> {
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

pub(crate) fn response(request_index: usize, body_bytes: usize) -> Vec<u8> {
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

pub(crate) fn validate_request(
    bytes: &[u8],
    request_index: usize,
    expected_body_bytes: usize,
) -> Result<(), HttpMessageError> {
    validate_http_message(
        bytes,
        &format!("POST /sssa-e2e/{request_index} HTTP/1.1"),
        &format!("X-SSSA-E2E-Request: {request_index}"),
        expected_body_bytes,
    )
}

pub(crate) fn validate_response(
    bytes: &[u8],
    request_index: usize,
    expected_body_bytes: usize,
) -> Result<(), HttpMessageError> {
    validate_http_message(
        bytes,
        "HTTP/1.1 200 OK",
        &format!("X-SSSA-E2E-Response: {request_index}"),
        expected_body_bytes,
    )
}

pub(crate) fn read_message<R: Read>(
    reader: &mut R,
    max_body_bytes: usize,
) -> Result<Vec<u8>, HttpMessageError> {
    let mut message = Vec::new();
    let mut buffer = [0_u8; HTTP_READ_CHUNK];
    loop {
        if let Some(expected_len) = complete_message_len(&message, max_body_bytes)?
            && message.len() >= expected_len
        {
            message.truncate(expected_len);
            return Ok(message);
        }
        let read = reader
            .read(&mut buffer)
            .map_err(|source| io_error("read HTTP message", source))?;
        if read == 0 {
            return Err(HttpMessageError::InvalidMessage(
                "stream ended before complete HTTP message".to_string(),
            ));
        }
        message.extend_from_slice(&buffer[..read]);
    }
}

pub(crate) fn chunk_size(bytes_len: usize, chunks: usize) -> usize {
    bytes_len.div_ceil(chunks).max(1)
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

fn validate_http_message(
    bytes: &[u8],
    start_line: &str,
    marker_header: &str,
    expected_body_bytes: usize,
) -> Result<(), HttpMessageError> {
    let message = std::str::from_utf8(bytes)
        .map_err(|error| HttpMessageError::InvalidMessage(error.to_string()))?;
    if !message.starts_with(start_line) {
        return Err(HttpMessageError::InvalidMessage(format!(
            "message did not start with {start_line}"
        )));
    }
    if !message.contains(marker_header) {
        return Err(HttpMessageError::InvalidMessage(format!(
            "message did not contain {marker_header}"
        )));
    }
    let Some((headers, body)) = message.split_once("\r\n\r\n") else {
        return Err(HttpMessageError::InvalidMessage(
            "message did not contain HTTP header terminator".to_string(),
        ));
    };
    let expected_content_length = format!("Content-Length: {expected_body_bytes}");
    if !headers.contains(&expected_content_length) {
        return Err(HttpMessageError::InvalidMessage(format!(
            "message did not contain {expected_content_length}"
        )));
    }
    if body.len() != expected_body_bytes {
        return Err(HttpMessageError::InvalidMessage(format!(
            "body length {} expected {expected_body_bytes}",
            body.len()
        )));
    }
    Ok(())
}

fn complete_message_len(
    bytes: &[u8],
    max_body_bytes: usize,
) -> Result<Option<usize>, HttpMessageError> {
    let Some(header_end) = header_end(bytes) else {
        return Ok(None);
    };
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|error| HttpMessageError::InvalidMessage(error.to_string()))?;
    let content_length = content_length(headers)?;
    if content_length > max_body_bytes {
        return Err(HttpMessageError::InvalidMessage(format!(
            "Content-Length {content_length} exceeds fixture max body {max_body_bytes}"
        )));
    }
    Ok(Some(header_end + "\r\n\r\n".len() + content_length))
}

fn header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows("\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
}

fn content_length(headers: &str) -> Result<usize, HttpMessageError> {
    let Some(value) = headers.lines().find_map(|line| {
        line.strip_prefix("Content-Length:")
            .map(|value| value.trim())
    }) else {
        return Err(HttpMessageError::InvalidMessage(
            "message did not contain Content-Length".to_string(),
        ));
    };
    value.parse::<usize>().map_err(|error| {
        HttpMessageError::InvalidMessage(format!("invalid Content-Length {value}: {error}"))
    })
}

fn io_error(action: &'static str, source: io::Error) -> HttpMessageError {
    HttpMessageError::Io { action, source }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn read_message_returns_exact_content_length_frame() -> Result<(), Box<dyn Error>> {
        let message = response(7, 24);
        let mut stream = Cursor::new([message.as_slice(), b"extra"].concat());

        let read = read_message(&mut stream, 24)?;

        assert_eq!(read, message);
        Ok(())
    }

    #[test]
    fn validate_traffic_config_rejects_empty_write_chunks() {
        let error = validate_traffic_config(&HttpTrafficConfig {
            write_chunks: 0,
            ..HttpTrafficConfig::default()
        })
        .expect_err("zero chunks must fail");

        assert!(error.to_string().contains("write-chunks"));
    }
}
